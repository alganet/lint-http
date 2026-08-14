// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! The `Forwarded` field's syntax, read as the grammar that defines it.
//!
//! Three productions meet in one field value and only one of them is HTTP's.
//! The list and its members are RFC 7239 §4's, a node identifier is §6's, and
//! `host` and `proto` are handed to RFC 3986's by §5.3 and §5.4 — which is where
//! a check reaching for `token` because the value looked token-shaped goes
//! wrong, since `token` admits characters none of those three productions do.

use crate::helpers::forwarded_node::NodeForm;
use crate::helpers::headers::{
    split_commas_respecting_quotes, split_semicolons_respecting_quotes, unescape_quoted_string,
};
use crate::helpers::token::find_invalid_token_char;
use crate::lint::Violation;
use crate::rules::Rule;

/// Every octet of a field line as the `char` of the same value.
///
/// `to_str` refuses every octet outside visible US-ASCII and this field's value
/// production does not: `qdtext` admits `obs-text`, so `foo="Ünix"` is a
/// conforming extension parameter that the old reader announced as a value "not
/// valid UTF-8" — a claim about an encoding, on a field where no encoding was
/// ever applied, standing in for the check that had something to say.
///
/// The mapping is a bijection. Every character the grammar is built from is
/// ASCII and crosses it unchanged, and every octet no production admits arrives
/// as a `char` no production admits either, at the check that owns it.
///
// cite(RFC 9110 § 5.6.4): "qdtext         = HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text"
fn field_line(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| b as char).collect()
}

/// A `for=` / `by=` value, after quoted-string unescaping: RFC 7239 §6's `node`.
///
/// The production is shared with the legacy `X-Forwarded-For` / `X-Forwarded-By`
/// family, which §7.4 converts into these very parameters, so it lives in
/// [`crate::helpers::forwarded_node`] and this function supplies the subject its
/// findings name. Returns the finding's text, or `None` when the value is a node.
// cite(RFC 7239 § 5.2): "The syntax of a "for" value, after potential quoted-string unescaping, conforms to the "node" ABNF described in Section 6."
// cite(RFC 7239 § 5.1): "The syntax of a "by" value, after potential quoted-string unescaping, conforms to the "node" ABNF described in Section 6."
fn validate_node(param: &str, value: &str) -> Option<String> {
    crate::helpers::forwarded_node::validate_node(value, NodeForm::Forwarded)
        .err()
        .map(|e| format!("Forwarded '{}' {}", param, e))
}

/// A `host=` value, after unescaping: the `Host` field's own ABNF.
// cite(RFC 7239 § 5.3): "The syntax for a "host" value, after potential quoted-string unescaping, MUST conform to the Host ABNF described in Section 5.4 of [RFC7230]."
// cite(RFC 9110 § 7.2, label: Host grammar): "Host = uri-host [ ":" port ]"
fn validate_host(value: &str) -> Option<String> {
    crate::helpers::uri::validate_host_and_optional_port(value)
        .err()
        .map(|e| format!("Forwarded 'host' is not a Host field value: {}", e))
}

/// A `proto=` value, after unescaping: a URI scheme name.
///
/// The MUST has two halves and this is the first. A scheme is also required to
/// be registered with IANA, and the registry is open — anyone may register one
/// through the procedures RFC 7595 sets out — so an unregistered name is not a
/// finding a fixed list in this file could reach. `http` and `https` are what
/// §5.4 calls typical, not what it permits.
///
// cite(RFC 7239 § 5.4): "The syntax of a "proto" value, after potential quoted-string unescaping, MUST conform to the URI scheme name as defined in Section 3.1 in [RFC3986] and registered with IANA according to [RFC4395]."
fn validate_proto(value: &str) -> Option<String> {
    crate::helpers::uri::validate_scheme_name(value)
        .err()
        .map(|e| format!("Forwarded 'proto' is not a URI scheme name: {}", e))
}

pub struct MessageForwardedHeaderValidity;

impl MessageForwardedHeaderValidity {
    /// One `forwarded-element`: the semicolon-separated sublist of pairs.
    ///
    /// The element arrives trimmed of the whitespace the *list* allows around
    /// its commas. Everything inside it is the element's own production, which
    /// has no `OWS` in it anywhere.
    fn check_element(&self, elem: &str, config: &crate::rules::RuleConfig) -> Option<Violation> {
        let violation = |message: String| {
            Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message,
            })
        };

        // §7.1's whitespace is the list's, between elements; the element itself
        // is `[ forwarded-pair ] *( ";" [ forwarded-pair ] )` and generates none
        // — not around a semicolon, not around the `=`. Asked here, quote-aware,
        // because SP and HTAB are `qdtext` and a value that quotes them is
        // conforming.
        //
        // cite(RFC 7239 § 7.1): "Note that an HTTP list allows white spaces to occur between the identifiers, and the list may be split over multiple header fields."
        // cite(RFC 7239 § 4, label: forwarded-element grammar): "forwarded-element = [ forwarded-pair ] *( ";" [ forwarded-pair ] )"
        if let Some(c) = whitespace_outside_quotes(elem) {
            return violation(format!(
                "Forwarded element holds whitespace its grammar does not admit ({:?} in '{}')",
                c, elem
            ));
        }

        // Each parameter at most once, in this element. Two elements naming the
        // same parameter are the ordinary case — a chain of proxies is a list of
        // elements each holding its own `for` — which is why the sentence says
        // "per field-value" and this set is per element.
        //
        // cite(RFC 7239 § 4): "Each parameter MUST NOT occur more than once per field-value."
        let mut seen: Vec<String> = Vec::new();

        for param in split_semicolons_respecting_quotes(elem) {
            // `[ forwarded-pair ]` — the pair is optional at every position, so
            // `for=192.0.2.1;;proto=https` names two parameters and nothing else.
            if param.is_empty() {
                continue;
            }

            // cite(RFC 7239 § 4, label: forwarded-pair grammar): "forwarded-pair = token "=" value value          = token / quoted-string"
            let Some((name, raw_value)) = param.split_once('=') else {
                return violation(format!(
                    "Forwarded parameter '{}' has no '=' and no value",
                    param
                ));
            };

            // `token` is `1*tchar`: a name is never empty, and `find_invalid_token_char`
            // says nothing about a string that has no characters to be wrong.
            if name.is_empty() {
                return violation(format!("Forwarded parameter '{}' has no name", param));
            }
            if let Some(c) = find_invalid_token_char(name) {
                return violation(format!(
                    "Forwarded parameter name '{}' is not a token ({:?} is not a tchar)",
                    name, c
                ));
            }

            // cite(RFC 7239 § 4): "The parameter names are case-insensitive."
            let name_lc = name.to_ascii_lowercase();
            if seen.contains(&name_lc) {
                return violation(format!(
                    "Forwarded element names the '{}' parameter more than once: '{}'",
                    name_lc, elem
                ));
            }
            seen.push(name_lc.clone());

            // The two alternatives of `value`. A quoted-string is checked as
            // one and then unescaped, because every sentence naming a
            // parameter's syntax below measures the value *after* unescaping; a
            // bare value has to be a token, which is what makes an address with
            // a port or a bracketed IPv6 literal a violation when it is written
            // unquoted, ':' and '[' being no part of `tchar`.
            //
            // cite(RFC 7239 § 4): "Note that as ":" and "[]" are not valid characters in "token", IPv6 addresses are written as "quoted-string"."
            // cite(RFC 7239 § 6): "It is important to note that an IPv6 address and any nodename with node-port specified MUST be quoted, since ":" is not an allowed character in "token"."
            let value = if raw_value.starts_with('"') {
                match unescape_quoted_string(raw_value) {
                    Ok(unescaped) => unescaped,
                    Err(e) => {
                        return violation(format!(
                            "Forwarded '{}' is not a well-formed quoted-string: {}",
                            name, e
                        ))
                    }
                }
            } else {
                if raw_value.is_empty() {
                    return violation(format!("Forwarded parameter '{}' has no value", param));
                }
                if let Some(c) = find_invalid_token_char(raw_value) {
                    return violation(format!(
                        "Forwarded '{}' value '{}' is neither a token ({:?} is not a tchar) nor a quoted-string",
                        name, raw_value, c
                    ));
                }
                raw_value.to_string()
            };

            if value.is_empty() {
                return violation(format!("Forwarded parameter '{}' has no value", param));
            }

            let finding = match name_lc.as_str() {
                "for" | "by" => validate_node(&name_lc, &value),
                "host" => validate_host(&value),
                "proto" => validate_proto(&value),
                // An extension parameter, and there is no list of them to check
                // against: the registry is IANA's, adding to it takes IETF
                // Review, and what this rule can measure — that the pair is a
                // `forwarded-pair` — has already been measured above.
                //
                // cite(RFC 7239 § 5.5): "All extension parameters SHOULD be registered in the "HTTP Forwarded Parameter" registry."
                // cite(RFC 7239 § 9): "New parameters and their values MUST conform with the forwarded-pair as defined in ABNF in Section 4."
                _ => None,
            };
            if let Some(message) = finding {
                return violation(message);
            }
        }

        None
    }

    /// One `Forwarded` field line.
    fn check_field_line(&self, line: &str, config: &crate::rules::RuleConfig) -> Option<Violation> {
        let violation = |message: String| {
            Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message,
            })
        };

        // Quote-aware, because a comma inside a quoted-string is `qdtext` and
        // not a member separator: the recipient's list reader used here before
        // cut `foo="a,b"` in two and reported both halves of a conforming value.
        // It also dropped every empty element, which is the recipient's
        // requirement standing in for the sender's — and the sender's is the one
        // a syntax rule measures, so the element that contributes nothing to the
        // list is reported here rather than silently discarded.
        //
        // The `#` in the field's own production is the bridge to the two
        // requirements below: RFC 7239 does not define what a list is, it
        // borrows HTTP's, so what HTTP asks of a sender using the construct is
        // asked of a sender of this field.
        //
        // cite(RFC 7239 § 3): "This specification uses the Augmented Backus-Naur Form (ABNF) notation of [RFC5234] with the list rule extension defined in Section 7 of [RFC7230]."
        // cite(RFC 7239 § 4, label: Forwarded grammar): "Forwarded   = 1#forwarded-element"
        // cite(RFC 9110 § 5.6.1.1): "In any production that uses the list construct, a sender MUST NOT generate empty list elements."
        let mut carried_an_element = false;
        let mut saw_an_empty_element = false;

        for elem in split_commas_respecting_quotes(line) {
            if elem.is_empty() {
                // `1#` is unsatisfied by a line of these, and the count is what
                // says so: an empty element is not one of the elements present.
                //
                // What is reported is the *list's* defect and not the element's.
                // `forwarded-element` is `[ forwarded-pair ] *( ";" [ forwarded-pair ] )`,
                // so an element holding no pair at all is a string the element
                // production generates; what no expansion of `1#` generates is a
                // member that contributes nothing to the list, which is the
                // sender requirement cited above and the mistake — merged values
                // — that the recipient one exists to absorb.
                //
                // cite(RFC 9110 § 5.6.1.2): "Empty elements do not contribute to the count of elements present."
                saw_an_empty_element = true;
                continue;
            }
            carried_an_element = true;
            if let Some(v) = self.check_element(elem, config) {
                return Some(v);
            }
        }

        if !carried_an_element {
            return violation(
                "Forwarded field line carries no forwarded-element, and the field is a list of at least one".into(),
            );
        }
        if saw_an_empty_element {
            return violation(format!(
                "Forwarded field line holds an empty element: '{}'",
                line
            ));
        }

        None
    }
}

impl Rule for MessageForwardedHeaderValidity {
    fn id(&self) -> &'static str {
        "message_forwarded_header_validity"
    }

    /// Both, and the response half is not a second place to look for the field:
    /// it is where finding the field at all is the finding. `Client` and `Both`
    /// dispatch identically in this engine — only `Server` filters, by skipping
    /// a transaction with no response — so the enum documents the two directions
    /// this rule has something to say about.
    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;

        // Every field line of the request's header section. A list may be split
        // over several of them and each holds whole elements — a comma is what
        // separates members, and joining the lines would put one there — so each
        // line is read on its own and the elements are the same elements.
        //
        // The request's *trailer* section is not read here. A `Forwarded` in one
        // is a finding, and it belongs to the sentence that says a sender may
        // not put a field in a trailer unless that field's definition permits it
        // — which is the trailer rule's, over the shared table of field names
        // this one now appears in.
        //
        // cite(RFC 7239 § 7.1): "Note that an HTTP list allows white spaces to occur between the identifiers, and the list may be split over multiple header fields."
        for hv in tx.request.headers.get_all("forwarded").iter() {
            if let Some(v) = self.check_field_line(&field_line(hv.as_bytes()), &config) {
                return Some(v);
            }
        }

        // The field is a request field, and this is not a scope note: §4 says so
        // in a sentence, and §8.2 says why — the value names every proxy between
        // the client and the origin, and a response carries it back to the party
        // it was hidden from. This rule used to walk the response to validate
        // the syntax of what it found there, under a comment saying the field
        // "can appear in responses per RFC 7239", with a test pinning that a
        // well-formed one was no finding at all.
        //
        // Both of the response's field sections, because §8.2's copy is a copy
        // wherever it lands.
        //
        // cite(RFC 7239 § 4): ""Forwarded" is only for use in HTTP requests and is not to be used in HTTP responses."
        // cite(RFC 7239 § 8.2): "This header field should never be copied into response messages by origin servers or intermediaries, as it can reveal the whole proxy chain to the client."
        if let Some(resp) = &tx.response {
            let in_trailers = resp
                .trailers
                .as_ref()
                .is_some_and(|t| t.contains_key("forwarded"));
            if resp.headers.contains_key("forwarded") || in_trailers {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!(
                        "Response carries a Forwarded field in its {} section: the field is only for use in HTTP requests, and copying it into a response reveals the proxy chain to the client",
                        match in_trailers && !resp.headers.contains_key("forwarded") {
                            true => "trailer",
                            false => "header",
                        }
                    ),
                });
            }
        }

        None
    }

    fn description(&self) -> &'static str {
        "Validates `Forwarded` (RFC 7239 §4) against the grammar that defines it: the field is a list of elements, each a semicolon-separated sublist of `name=value` pairs whose names are tokens and whose values are tokens or quoted-strings, with no whitespace inside an element and no parameter named twice in one element.\n\nThe four registered parameters are checked against the sentences that define them. `for` and `by` must be a node identifier (RFC 7239 §6): an IPv4 address, a bracketed IPv6 address, `unknown`, or an obfuscated identifier — which **must begin with an underscore** and hold only letters, digits, `.`, `_` and `-` — each optionally followed by `:` and a port of one to five digits or an obfuscated port. An IPv6 address, and any node identifier carrying a port, must be written as a quoted-string, since `:` and `[]` are not token characters. `host` must conform to the `Host` field ABNF (RFC 9110 §7.2) and `proto` to a URI scheme name (RFC 3986 §3.1).\n\nA `Forwarded` field in a **response** is reported: RFC 7239 §4 restricts the field to requests, and §8.2 explains that copying it into a response reveals the whole proxy chain to the client.\n\nWhat this rule does not check: an extension parameter's name against the IANA \"HTTP Forwarded Parameters\" registry, or a `proto` value against the URI scheme registry — both registries are open and live elsewhere. A `Forwarded` field in a trailer section is reported by the trailer-fields rule, not here. The IPv6 recommendation of RFC 7239 §6.1 (RFC 5952 form: lowercase, zeroes compressed) is a SHOULD, and a value that parses but is written differently is reported as one."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 7239",
                section: Some("4"),
                url: "https://www.rfc-editor.org/rfc/rfc7239.html#section-4",
                note: "The field's grammar, the case-insensitivity of parameter names, the MUST NOT on naming a parameter twice in one element, and the sentence restricting the field to requests",
            },
            crate::rules::SpecRef {
                spec: "RFC 7239",
                section: Some("6"),
                url: "https://www.rfc-editor.org/rfc/rfc7239.html#section-6",
                note: "`node`, `nodename`, `node-port`: the obfuscated forms MUST begin with an underscore, a numeric port is one to five digits, and an address with a port MUST be quoted. §6.1's SHOULD asks for the RFC 5952 textual form",
            },
            crate::rules::SpecRef {
                spec: "RFC 7239",
                section: Some("5"),
                url: "https://www.rfc-editor.org/rfc/rfc7239.html#section-5",
                note: "The four registered parameters. `host` MUST conform to the Host ABNF and `proto` to a URI scheme name; extension parameters SHOULD be registered, in a registry this rule does not hold",
            },
            crate::rules::SpecRef {
                spec: "RFC 7239",
                section: Some("8.2"),
                url: "https://www.rfc-editor.org/rfc/rfc7239.html#section-8.2",
                note: "Why a response must not carry the field: it reveals the whole proxy chain to the client",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("7.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-7.2",
                note: "`Host = uri-host [ \":\" port ]`, which §5.3 makes the syntax of a `host` parameter",
            },
            crate::rules::SpecRef {
                spec: "RFC 3986",
                section: Some("3.1"),
                url: "https://www.rfc-editor.org/rfc/rfc3986.html#section-3.1",
                note: "`scheme = ALPHA *( ALPHA / DIGIT / \"+\" / \"-\" / \".\" )`, which §5.4 makes the syntax of a `proto` parameter",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "Forwarded: for=192.0.2.43;proto=https;by=203.0.113.5\n\nForwarded: for=\"[2001:db8::1]\";host=example.com\n\nForwarded: for=\"192.0.2.43:47011\", for=_gazonk\n\nForwarded: for=unknown;by=_SEVKISEK",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "Forwarded: for=999.999.999.999\n# not an IPv4 address, and not a node identifier of any other kind\n\nForwarded: for=x-foo\n# an obfuscated identifier must begin with an underscore\n\nForwarded: for=192.0.2.43:4711\n# a node identifier with a port must be quoted: ':' is not a token character\n\nForwarded: for=\"192.0.2.43:123456\"\n# a numeric node-port is one to five digits\n\nForwarded: for=192.0.2.43;for=198.51.100.17\n# a parameter may be named only once per element\n\nForwarded: proto=ht_tp\n# a URI scheme name holds no underscore",
            },
        ]
    }
}

/// The first whitespace character outside a quoted-string, if any.
///
/// Written here rather than reached for from the splitters because it is the
/// same walk they make: a DQUOTE opens and closes a string, a backslash inside
/// one escapes the octet after it, and neither means anything outside one.
// cite(RFC 9110 § 5.6.4): "quoted-pair    = "\" ( HTAB / SP / VCHAR / obs-text )"
fn whitespace_outside_quotes(s: &str) -> Option<char> {
    let mut in_quote = false;
    let mut escaped = false;
    for c in s.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        match c {
            '\\' if in_quote => escaped = true,
            '"' => in_quote = !in_quote,
            c if c.is_ascii_whitespace() && !in_quote => return Some(c),
            _ => {}
        }
    }
    None
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &MessageForwardedHeaderValidity;

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;

    /// The rule's verdict on one request carrying these `Forwarded` field lines.
    fn judge(values: &[&str]) -> Option<String> {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[]);
        for value in values {
            tx.request.headers.append(
                "forwarded",
                HeaderValue::from_bytes(value.as_bytes()).expect("a field value"),
            );
        }
        MessageForwardedHeaderValidity
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &crate::test_helpers::make_test_config_with_enabled_rules(&[
                    "message_forwarded_header_validity",
                ]),
            )
            .map(|v| v.message)
    }

    /// One field line, which is what all but a couple of the cases below need.
    fn judge_one(value: &str) -> Option<String> {
        judge(&[value])
    }

    #[test]
    fn the_field_values_the_rfc_prints_are_all_accepted() {
        // §4's examples, §6's, §6.3's, §7.1's three equivalent forms, §7.4's and
        // §7.5's. Running a specification's own examples through the rule that
        // reads the field is worth more than any test written from the same
        // reading of the spec as the code.
        for value in [
            "for=\"_gazonk\"",
            "For=\"[2001:db8:cafe::17]:4711\"",
            "for=192.0.2.60;proto=http;by=203.0.113.43",
            "for=192.0.2.43, for=198.51.100.17",
            "for=\"192.0.2.43:47011\"",
            "for=\"[2001:db8:cafe::17]:47011\"",
            "for=_hidden, for=_SEVKISEK",
            "for=192.0.2.43,for=\"[2001:db8:cafe::17]\",for=unknown",
            "for=192.0.2.43, for=\"[2001:db8:cafe::17]\", for=unknown",
            "for=192.0.2.43",
            "for=192.0.2.43, for=198.51.100.17;by=203.0.113.60;proto=http;host=example.com",
        ] {
            assert_eq!(judge_one(value), None, "{value}");
        }
    }

    #[test]
    fn an_obfuscated_identifier_must_begin_with_an_underscore() {
        // Every one of these is a `token`, which is what the rule used to ask.
        // None of them is an `obfnode`.
        for value in ["for=x-foo", "for=hidden", "by=proxy1", "for=\"x-foo:8080\""] {
            let message = judge_one(value).unwrap_or_else(|| panic!("{value}"));
            assert!(message.contains("node identifier"), "{value}: {message}");
        }
        for value in ["for=_foo", "by=_SEVKISEK", "for=_a.b-c_d"] {
            assert_eq!(judge_one(value), None, "{value}");
        }
        // The characters after the underscore are not `tchar`'s either: `~` is
        // one and is no part of an obfuscated identifier.
        assert!(judge_one("for=_a~b").is_some());
    }

    #[test]
    fn a_node_port_is_five_digits_or_an_obfuscated_port() {
        // `port = 1*5DIGIT` has no range in it. The shared TCP-port reader this
        // rule used to call reports everything over 65535 and knows nothing of
        // an obfuscated port at all; `99999` is where the two part, and it is
        // five digits.
        for value in [
            "for=\"192.0.2.1:0\"",
            "for=\"192.0.2.1:99999\"",
            "for=\"192.0.2.1:080\"",
            "for=\"192.0.2.1:_obf\"",
            "for=\"[2001:db8::1]:_obf\"",
            "for=\"unknown:8080\"",
        ] {
            assert_eq!(judge_one(value), None, "{value}");
        }
        for value in [
            "for=\"192.0.2.1:123456\"",
            "for=\"192.0.2.1:\"",
            "for=\"192.0.2.1:8o8\"",
            "for=\"[2001:db8::1]:x\"",
        ] {
            let message = judge_one(value).unwrap_or_else(|| panic!("{value}"));
            assert!(message.contains("node-port"), "{value}: {message}");
        }
    }

    #[test]
    fn an_address_with_a_port_and_an_ipv6_literal_must_be_quoted() {
        // `:` and `[` are no part of `tchar`, so an unquoted value holding one
        // is not a `value` at all — which is the sentence §6 spells out for
        // exactly this field.
        // The sentence §6 spells out is about a node identifier, and the
        // production behind it is `value = token / quoted-string`, which every
        // parameter is measured against — so a `host` with a port is quoted for
        // the same reason a `for` with one is.
        for value in [
            "for=192.0.2.1:8080",
            "for=[2001:db8::1]",
            "for=[2001:db8::1]:8080",
            "host=example.com:8080",
            "host=[2001:db8::1]:8080",
        ] {
            let message = judge_one(value).unwrap_or_else(|| panic!("{value}"));
            assert!(
                message.contains("neither a token") && message.contains("quoted-string"),
                "{value}: {message}"
            );
        }
    }

    #[test]
    fn an_unbracketed_ipv6_address_is_reported_as_one() {
        let message = judge_one("for=\"2001:db8::1\"").expect("a finding");
        assert!(message.contains("unbracketed IPv6"), "{message}");
    }

    #[test]
    fn a_parameter_may_be_named_once_per_element() {
        // Two elements naming `for` is the ordinary case: that is what a chain
        // of proxies looks like. Twice inside one element is the MUST NOT.
        assert_eq!(judge_one("for=192.0.2.1, for=192.0.2.2"), None);
        for value in [
            "for=192.0.2.1;for=192.0.2.2",
            "for=192.0.2.1;FOR=192.0.2.2",
            "host=a.example;proto=https;host=b.example",
        ] {
            let message = judge_one(value).unwrap_or_else(|| panic!("{value}"));
            assert!(message.contains("more than once"), "{value}: {message}");
        }
    }

    #[test]
    fn an_element_admits_no_whitespace_of_its_own() {
        for value in [
            "for=192.0.2.1; proto=https",
            "for=192.0.2.1 ;proto=https",
            "for = 192.0.2.1",
            "for=192.0.2.1; ;proto=https",
        ] {
            let message = judge_one(value).unwrap_or_else(|| panic!("{value}"));
            assert!(message.contains("whitespace"), "{value}: {message}");
        }
        // The list's own whitespace, around its commas, is §7.1's and is fine —
        // and whitespace inside a quoted-string is `qdtext`.
        assert_eq!(judge_one("for=192.0.2.1,  for=192.0.2.2"), None);
        assert_eq!(judge_one("foo=\"a b\""), None);
    }

    #[test]
    fn an_empty_element_is_the_senders_defect_and_not_dropped() {
        // The recipient's list reader drops these, which is what §5.6.1.2 asks
        // of a recipient and the opposite of what a syntax rule measures.
        for value in [
            "for=192.0.2.1,,for=192.0.2.2",
            ", for=192.0.2.1",
            "for=192.0.2.1,",
        ] {
            let message = judge_one(value).unwrap_or_else(|| panic!("{value}"));
            assert!(message.contains("empty element"), "{value}: {message}");
        }
        for value in ["", " ", ","] {
            let message = judge_one(value).unwrap_or_else(|| panic!("{value:?}"));
            assert!(
                message.contains("no forwarded-element"),
                "{value:?}: {message}"
            );
        }
    }

    #[test]
    fn a_comma_inside_a_quoted_string_is_not_a_member_separator() {
        // Split blindly on commas, this conforming value became two elements
        // and both halves were reported.
        assert_eq!(judge_one("foo=\"a,b\""), None);
        assert_eq!(judge_one("foo=\"a;b\""), None);
        assert_eq!(judge_one("foo=\"a\\\"b\""), None);
    }

    #[test]
    fn a_host_parameter_is_measured_against_the_host_abnf() {
        for value in [
            "host=example.com",
            "host=\"example.com:8080\"",
            "host=\"example.com:\"",
            "host=\"example.com:99999\"",
            "host=\"[2001:db8::1]:8080\"",
            // `uri-host` is wider than `token`, so a registered name holding a
            // sub-delimiter is a `value` only in its quoted form.
            "host=\"a(b).example\"",
        ] {
            assert_eq!(judge_one(value), None, "{value}");
        }
        for value in ["host=\"user@host\"", "host=\"exa mple\"", "host=\"a^b\""] {
            let message = judge_one(value).unwrap_or_else(|| panic!("{value}"));
            assert!(message.contains("Host field value"), "{value}: {message}");
        }
    }

    #[test]
    fn a_proto_parameter_is_a_uri_scheme_name() {
        for value in ["proto=http", "proto=https", "proto=coap+ws"] {
            assert_eq!(judge_one(value), None, "{value}");
        }
        // All three are tokens, and none is a scheme name.
        for value in ["proto=ht_tp", "proto=9https", "proto=ht%tp"] {
            let message = judge_one(value).unwrap_or_else(|| panic!("{value}"));
            assert!(message.contains("URI scheme name"), "{value}: {message}");
        }
    }

    #[test]
    fn an_ipv6_address_is_asked_for_the_recommended_textual_form() {
        for value in [
            "for=\"[2001:DB8::1]\"",
            "for=\"[2001:db8:0:0:0:0:0:1]\"",
            "for=\"[2001:db8::0:1]\"",
        ] {
            let message = judge_one(value).unwrap_or_else(|| panic!("{value}"));
            assert!(
                message.contains("recommended textual representation"),
                "{value}: {message}"
            );
        }
        // Rust's own rendering is the recommended one, which is what makes the
        // comparison honest: lowercase, the longest run of zeroes compressed,
        // and the mixed form for an IPv4-mapped address.
        for value in [
            "for=\"[2001:db8::1]\"",
            "for=\"[::1]\"",
            "for=\"[::ffff:192.0.2.1]\"",
        ] {
            assert_eq!(judge_one(value), None, "{value}");
        }
    }

    #[test]
    fn a_pair_needs_a_token_name_and_a_value() {
        for (value, expected) in [
            ("for", "no '=' and no value"),
            ("=192.0.2.1", "has no name"),
            ("foo=", "has no value"),
            ("for=\"\"", "has no value"),
            ("@=1", "is not a token"),
            ("foo=\"bar\"x", "well-formed quoted-string"),
            ("foo=bad@value", "neither a token"),
        ] {
            let message = judge_one(value).unwrap_or_else(|| panic!("{value}"));
            assert!(message.contains(expected), "{value}: {message}");
        }
        // An extension parameter is not checked beyond the pair: there is no
        // list of registered names in this rule to check it against.
        assert_eq!(judge_one("foo=bar"), None);
        assert_eq!(judge_one("foo=\"bar baz\""), None);
    }

    #[test]
    fn obs_text_in_a_quoted_string_is_not_a_finding_about_utf_8() {
        // `qdtext` admits `obs-text`, so this extension parameter conforms. The
        // reader that refused it announced a value "not valid UTF-8" — which is
        // neither what it checked nor true of the octets on the wire.
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[]);
        tx.request.headers.append(
            "forwarded",
            HeaderValue::from_bytes(b"foo=\"\xdcnix\"").expect("a field value"),
        );
        let rule = MessageForwardedHeaderValidity;
        assert!(rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
            )
            .is_none());

        // The same octet outside a quoted-string is a finding, and about the
        // thing that is actually wrong with it.
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[]);
        tx.request.headers.append(
            "forwarded",
            HeaderValue::from_bytes(b"for=\xff").expect("a field value"),
        );
        let message = rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
            )
            .expect("a finding")
            .message;
        assert!(message.contains("neither a token"), "{message}");
    }

    #[test]
    fn every_field_line_is_read() {
        assert_eq!(judge(&["for=192.0.2.1", "for=192.0.2.2"]), None);
        assert!(judge(&["for=192.0.2.1", "for=999.999.999.999"]).is_some());
    }

    #[test]
    fn a_response_carrying_the_field_is_the_finding() {
        // The field is only for use in requests. This rule used to validate the
        // syntax of a response's `Forwarded` and pass a well-formed one.
        let rule = MessageForwardedHeaderValidity;
        let config = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);

        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("forwarded", "for=192.0.2.1")],
        );
        let message = rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &config,
            )
            .expect("a finding")
            .message;
        assert!(
            message.contains("only for use in HTTP requests"),
            "{message}"
        );

        // Including in the trailer section: a copy is a copy wherever it lands,
        // and the message names the section it was found in.
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().expect("a response").trailers = Some(
            crate::test_helpers::make_headers_from_pairs(&[("forwarded", "for=192.0.2.1")]),
        );
        let message = rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &config,
            )
            .expect("a finding")
            .message;
        assert!(message.contains("its trailer section"), "{message}");

        // A response with no `Forwarded` of its own is not a finding, whatever
        // the request carried.
        let tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        assert!(rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &config,
            )
            .is_none());
    }

    #[test]
    fn published_examples_are_judged_the_way_they_are_labelled() {
        use crate::rules::Compliance;

        let mut saw_a_finding = false;
        for ex in MessageForwardedHeaderValidity.examples() {
            for block in ex.snippet.split("\n\n") {
                let values: Vec<&str> = block
                    .lines()
                    .filter(|l| !l.starts_with('#'))
                    .map(|l| {
                        l.split_once(": ")
                            .unwrap_or_else(|| panic!("not a field line: {l:?}"))
                            .1
                    })
                    .collect();
                let found = judge(&values);
                match ex.compliance {
                    Compliance::Compliant => assert!(
                        found.is_none(),
                        "rule reports its Compliant example {block:?}: {found:?}"
                    ),
                    Compliance::NonCompliant => {
                        assert!(
                            found.is_some(),
                            "rule accepts its NonCompliant example {block:?}"
                        );
                        saw_a_finding = true;
                    }
                }
            }
        }
        assert!(saw_a_finding, "the guard ran without exercising a finding");
    }

    #[test]
    fn an_obs_text_octet_outside_a_quoted_string_is_not_called_whitespace() {
        // The octet arrives as the `char` of the same value, and `U+00A0` is
        // whitespace to Unicode and `obs-text` to HTTP. The finding is about the
        // production the octet is standing outside of, not about spacing.
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[]);
        tx.request.headers.append(
            "forwarded",
            HeaderValue::from_bytes(b"foo=a\xa0b").expect("a field value"),
        );
        let rule = MessageForwardedHeaderValidity;
        let message = rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
            )
            .expect("a finding")
            .message;
        assert!(message.contains("neither a token"), "{message}");
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "message_forwarded_header_validity");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
