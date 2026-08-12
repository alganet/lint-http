// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct ClientRequestUriPercentEncodingValid;

impl Rule for ClientRequestUriPercentEncodingValid {
    fn id(&self) -> &'static str {
        "client_request_uri_percent_encoding_valid"
    }

    /// The characters measured here were written by the client that resolved a
    /// URI reference into a target URI and sent its components, so the rule has
    /// to run on a capture whose upstream never answered as well as on a
    /// complete exchange. `Server` means "skip when there is no response",
    /// which would skip exactly the request-only lint -- and the octets were
    /// already on the wire when the request was sent.
    // cite(RFC 9110 § 7.1): "To perform an action on a "target resource", the client sends a request message containing enough components of its parsed target URI to enable recipients to identify that same resource."
    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Client
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        // What this field holds is version-specific -- an HTTP/1.x
        // request-target, or the target URI the transport reassembled from
        // pseudo-header fields -- and the one name that covers both is § 7.1's,
        // where the components a message carries are collectively the request
        // target whatever the major version puts them in. Neither reading
        // changes the question asked below: `:path` is the path and query parts
        // of the target URI, so the characters are the same productions'
        // characters on all three versions and the rule is not version-gated.
        // cite(RFC 9110 § 7.1): "For historical reasons, the parsed target URI components, collectively referred to as the "request target", are sent within the message control data and the Host header field"
        // cite(RFC 9113 § 8.3.1): "The ":path" pseudo-header field includes the path and query parts of the target URI"
        // cite(RFC 9114 § 4.3.1): "Contains the path and query parts of the target URI"
        let target = tx.request.uri.as_str();

        // Both findings below are "this derives from no production", and the
        // productions are not HTTP's own: § 4.1 adopts the generic syntax's
        // rules by name for the elements that carry a URI, which is what carries
        // § 2.2's sender MUST NOT onto a percent-encoding.
        // cite(RFC 9110 § 4.1): "The definitions of "URI-reference", "absolute-URI", "relative-part", "authority", "port", "host", "path-abempty", "segment", and "query" are adopted from the URI generic syntax."
        // cite(RFC 9110 § 2.2): "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules."

        // The triplet is three characters and the '%' is the first of them, so
        // the question is asked of the whole target rather than of a component:
        // a '%' means the same thing in a path, a query, a host and a scheme's
        // rootless path, and the helper carries the production. Hexadecimal case
        // is not part of it -- `description()` records which sentence is
        // declined there and why.
        // cite(RFC 3986 § 2.4): "Because the percent ("%") character serves as the indicator for percent-encoded octets, it must be percent-encoded as "%25" for that octet to be used as data within a URI."
        // cite(RFC 3986 § 2.4): "Once produced, a URI is always in its percent-encoded form."
        // cite(RFC 3986 § 2.4): "When a URI is dereferenced, the components and subcomponents significant to the scheme-specific dereferencing process (if any) must be parsed and separated before the percent-encoded octets within those components can be safely decoded, as otherwise the data may be mistaken for component delimiters."
        if let Some(msg) = crate::helpers::uri::check_percent_encoding(target) {
            // Read after the finding is certain: parsing the config is several
            // map probes and a hash of the rule id, where the scan above walks a
            // string the transaction already holds.
            let severity = crate::rules::parse_rule_config(cfg, self.id())
                .ok()?
                .severity;

            // A target read back from a capture can hold characters that print
            // as nothing or, worse, print as something else: an escape sequence
            // in a finding is a finding nobody can read.
            let shown = crate::helpers::headers::shown_in_finding(target);

            return Some(Violation {
                rule: self.id().into(),
                severity,
                message: format!(
                    "Request target '{shown}': {msg}. The percent character is the indicator for a \
                     percent-encoded octet and opens a triplet -- itself and two hexadecimal \
                     digits -- so one meant as data is written '%25'. Once produced a URI is \
                     always in its percent-encoded form, which is why what follows a '%' is read \
                     as an encoding whatever the sender meant by it, and why a recipient that \
                     decodes before it has separated the components can take the result for a \
                     delimiter"
                ),
            });
        }

        // The other half of the same mechanism: percent-encoding is what carries
        // an octet whose character the URI alphabet does not have, so a
        // character outside that alphabet is a percent-encoding that was never
        // written. The helper answers the alphabet question only -- '%' is one
        // of its characters, and the check above is what obliges that '%' to
        // open a triplet -- so the two branches never report one character
        // twice.
        //
        // The alphabet measured is the *union* of every component's, and that is
        // the rule's floor rather than its ceiling: the generic syntax writes
        // several alphabets, and a character can be inside the union and outside
        // the component it was written in -- '[' derives from none of the three
        // productions below, and this rule reports it in none of them, because it
        // does not split the target into components. What it reports is a
        // character no component admits, which is a finding whichever component
        // it sits in. `description()` publishes the half that is left.
        // cite(RFC 3986 § 3.3, label: pchar): "pchar         = unreserved / pct-encoded / sub-delims / ":" / "@""
        // cite(RFC 3986 § 3.4, label: query): "query       = *( pchar / "/" / "?" )"
        // cite(RFC 3986 § 3.2.2, label: reg-name): "reg-name    = *( unreserved / pct-encoded / sub-delims )"
        // cite(RFC 3986 § 2.1): "A percent-encoding mechanism is used to represent a data octet in a component when that octet's corresponding character is outside the allowed set or is being used as a delimiter of, or within, the component."
        // cite(RFC 3986 § 2): "A URI is composed from a limited set of characters consisting of digits, letters, and a few graphic symbols."
        // cite(RFC 3986 § 2): "The ABNF notation defines its terminal values to be non-negative integers (codepoints) based on the US-ASCII coded character set [ASCII]."
        // cite(RFC 3986 § 2): "the integer values used by the ABNF must be mapped back to their corresponding characters via US-ASCII in order to complete the syntax rules."
        if let Some(ch) = crate::helpers::uri::find_non_uri_char(target) {
            let severity = crate::rules::parse_rule_config(cfg, self.id())
                .ok()?
                .severity;

            let shown = crate::helpers::headers::shown_in_finding(target);
            let shown_char = crate::helpers::headers::shown_in_finding(&ch.to_string());

            return Some(Violation {
                rule: self.id().into(),
                severity,
                message: format!(
                    "Request target '{shown}' contains '{shown_char}' (U+{:04X}), which is not one \
                     of the characters a URI is composed from -- digits, letters and a few graphic \
                     symbols, the notation's terminals being US-ASCII codepoints. An octet whose \
                     character is outside that set is carried by percent-encoding it, and this one \
                     was written raw, so no component's production derives this target",
                    ch as u32
                ),
            });
        }

        None
    }

    fn title(&self) -> Option<&'static str> {
        Some("Client Request URI Percent Encoding Valid")
    }

    fn description(&self) -> &'static str {
        "Reads the characters of the request target and asks whether it is properly percent-encoded — percent-encoding being the one mechanism a URI has for carrying an octet whose character is outside the set a URI may be written with (RFC 3986 §2.1).\n\n**Every `%` opens a triplet.** `pct-encoded = \"%\" HEXDIG HEXDIG`, and the percent character has no second role: it is *\"the indicator for percent-encoded octets\"*, so one meant as data is written `%25` (RFC 3986 §2.4). A `%` at the end of the value, or one followed by anything that is not two hexadecimal digits, therefore derives from no production. The two are reported as themselves — a run that stops short and a run with a non-hex character are different mistakes — and both matter to the recipient rather than only to the sender: *\"Once produced, a URI is always in its percent-encoded form\"*, so what follows a `%` is read as an encoding whatever was meant by it, and §2.4 warns that octets decoded before their components are separated can be taken for delimiters.\n\n**Every other character has to be one a URI is composed from.** A URI is written with *\"digits, letters, and a few graphic symbols\"* (RFC 3986 §2), and the notation's terminals are US-ASCII codepoints — so `{`, `}`, `|`, `\\`, `^`, `` ` ``, `<`, `>`, `\"`, a space and every non-ASCII character are outside the alphabet, whatever component they sit in. Each is an octet §2.1 asks to be percent-encoded, and writing it raw is the same defect as a malformed triplet seen from the other side: `/caf\u{e9}/` is reported and `/caf%C3%A9/` is not. Both branches rest on RFC 9110 §2.2's *\"A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules\"*, which reaches a URI production because §4.1 adopts the generic syntax's rules by name for the HTTP elements that carry one.\n\n**The rule is not version-gated.** An HTTP/1.x capture records the request-target from the request-line; HTTP/2 and HTTP/3 send no request-line, and what is recorded is the target URI their transport reassembled from pseudo-header fields, whose `:path` is the path and query parts of that same target URI (RFC 9113 §8.3.1, RFC 9114 §4.3.1). The characters are the same productions' characters either way, and RFC 9110 §7.1's *\"request target\"* is the name that covers all three.\n\n**Hexadecimal case is not part of the check, and that is a decision.** RFC 3986 §2.1 recommends uppercase — *\"For consistency, URI producers and normalizers should use uppercase hexadecimal digits for all percent-encodings\"* — and the sentence immediately before it is why the recommendation is not a finding: the digits are *\"equivalent\"*, and two URIs differing only in that case are the same URI. The notation says it from the other direction, a quoted string in an ABNF rule being case-insensitive (RFC 5234 §2.3), so `%2f` derives from `HEXDIG` exactly as `%2F` does. RFC 3986 states no BCP 14 requirement anywhere in the document; reporting a lowercase digit would be enforcing a preference as a rule.\n\n**What this rule can and cannot see.** A malformed triplet survives the proxy's own capture path intact — the URI parser it builds `tx.request.uri` with accepts `%`, `%2`, `%2G` and `%zz` without complaint — so these findings are reachable on live traffic, unlike a fragment, which that same parser removes before a transaction exists. The character half is reachable in part: `{`, `}`, `|`, `\\`, `^`, `\"` and non-ASCII characters all reach a capture, while `<`, `>`, `` ` `` and a space are refused before one is written and arrive only in a capture recorded elsewhere and read back through the `lint` subcommand. A test pins that boundary.\n\n**What this rule does not decide.** Whether a character sits in a component that admits it. The alphabet measured is the union of every component's, and the generic syntax writes several: `pchar` admits `:` and `@`, `query` adds `/` and `?`, `reg-name` has neither (RFC 3986 §3.3, §3.4, §3.2.2). A `[` is in the union — the host productions use it for an IP-literal — and derives from none of those three, so `/a[b]c` is not reported here, because splitting the target into its components is not something this rule does. What it reports is a character that no component admits, which is a finding wherever it sits. Which of the four forms an HTTP/1.x request-target derives from, and whether the method may use that form, is `client_request_target_form_checks` — which also reports whitespace in a request-line's target on a sentence of its own (RFC 9112 §3.2 excludes whitespace from the request-target by name and asks a recipient not to autocorrect it), so a space in an HTTP/1.x target draws two findings saying two different things about it. Whether the target carries a fragment is `client_request_target_no_fragment`. Whether an encoded octet *should* have been left decoded — RFC 3986 §6.2.2.2's normalization of a percent-encoded unreserved character — is nobody's finding: the two spellings identify the same resource."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 3986",
                section: Some("2.1"),
                url: "https://www.rfc-editor.org/rfc/rfc3986.html#section-2.1",
                note: "Percent-Encoding: the triplet production, and percent-encoding as the mechanism for an octet whose character is outside the allowed set",
            },
            crate::rules::SpecRef {
                spec: "RFC 3986",
                section: Some("2"),
                url: "https://www.rfc-editor.org/rfc/rfc3986.html#section-2",
                note: "Characters: the limited set a URI is composed from, whose terminals the notation maps back through US-ASCII",
            },
            crate::rules::SpecRef {
                spec: "RFC 3986",
                section: Some("2.4"),
                url: "https://www.rfc-editor.org/rfc/rfc3986.html#section-2.4",
                note: "When to Encode or Decode: a URI on the wire is already in its percent-encoded form, a '%' meant as data is written %25, and octets decoded before their components are separated can be taken for delimiters",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("4.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-4.1",
                note: "URI References: the generic syntax's productions are adopted by name for the HTTP elements that carry a URI",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("2.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-2.2",
                note: "The sender MUST NOT that a value matching no production breaks",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("7.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-7.1",
                note: "Determining the Target Resource: the components sent are collectively the request target on every major protocol version",
            },
            crate::rules::SpecRef {
                spec: "RFC 5234",
                section: Some("2.3"),
                url: "https://www.rfc-editor.org/rfc/rfc5234.html#section-2.3",
                note: "ABNF strings are case insensitive, which is why a lowercase hexadecimal digit derives from HEXDIG",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("Request"),
                snippet: "GET /path%20with%20spaces HTTP/1.1\nHost: example.com",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(characters outside the URI alphabet, encoded)"),
                snippet: "GET /caf%C3%A9/menu?q=100%25 HTTP/1.1\nHost: example.com",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(a triplet that stops short, or is not two hex digits)"),
                snippet: "GET /path%2 HTTP/1.1\nGET /path%GG HTTP/1.1\nGET /100% HTTP/1.1",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(characters no URI is composed from, written raw)"),
                snippet: "GET /caf\u{e9}/menu HTTP/1.1\nGET /path/{id} HTTP/1.1\nGET /a|b HTTP/1.1",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ClientRequestUriPercentEncodingValid;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn judge(uri: &str, version: &str) -> Option<String> {
        let rule = ClientRequestUriPercentEncodingValid;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.uri = uri.to_string();
        tx.request.version = version.to_string();

        let config = crate::test_helpers::make_test_config_with_severity(rule.id(), "error");

        rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config,
        )
        .map(|v| {
            assert_eq!(v.rule, "client_request_uri_percent_encoding_valid");
            v.message
        })
    }

    #[rstest]
    #[case("/path/to/resource", false)]
    #[case("/path%20with%20spaces", false)]
    #[case("/path%2Fwith%2Fslashes", false)]
    #[case("/%41BC", false)]
    #[case("/mix%2fCase%2F", false)]
    #[case("/incomplete%2", true)]
    #[case("/endswith%", true)]
    #[case("/bad%2Gchar", true)]
    #[case("/bad%zz", true)]
    fn a_percent_opens_a_triplet_or_nothing(#[case] uri: &str, #[case] expect_violation: bool) {
        assert_eq!(judge(uri, "HTTP/1.1").is_some(), expect_violation);
    }

    /// The recommendation to write `A` through `F` in uppercase is declined, and
    /// both spellings derive from `HEXDIG`, so neither is reported.
    #[rstest]
    #[case("/%2f")]
    #[case("/%2F")]
    #[case("/%c3%a9")]
    #[case("/%C3%A9")]
    fn hexadecimal_case_is_not_a_finding(#[case] uri: &str) {
        assert_eq!(judge(uri, "HTTP/1.1"), None);
    }

    /// The three characters a percent meant as data is written with are the one
    /// spelling of it that is not a finding.
    #[test]
    fn a_percent_carried_as_data_is_the_triplet_for_it() {
        assert_eq!(judge("/100%25", "HTTP/1.1"), None);
        assert!(judge("/100%", "HTTP/1.1").is_some());
    }

    #[rstest]
    #[case("/caf\u{e9}/menu", '\u{e9}')]
    #[case("/path/{id}", '{')]
    #[case("/a|b", '|')]
    #[case("/a\\b", '\\')]
    #[case("/a^b", '^')]
    #[case("/a\"b", '"')]
    #[case("/a<b>c", '<')]
    #[case("/a`b", '`')]
    #[case("/pa th", ' ')]
    fn a_character_no_uri_is_composed_from_is_reported(#[case] uri: &str, #[case] ch: char) {
        let msg = judge(uri, "HTTP/1.1").expect("must be reported");
        assert!(
            msg.contains("is not one of the characters a URI is composed from"),
            "{msg}"
        );
        assert!(msg.contains(&format!("(U+{:04X})", ch as u32)), "{msg}");
    }

    /// The reserved and unreserved characters are the alphabet, so a target
    /// built from them is clean however unusual it looks -- and so are the two
    /// method-specific forms, which are `client_request_target_form_checks`'s
    /// question and not this one's.
    /// The union is the floor and not the ceiling: `[` derives from neither
    /// `pchar` nor `query` nor `reg-name`, and is not reported, because the
    /// target is never split into the components those productions belong to.
    #[test]
    fn a_character_in_the_wrong_component_is_not_this_rules_finding() {
        assert_eq!(judge("/a[b]c", "HTTP/1.1"), None);
    }

    #[rstest]
    #[case("/a:b@c")]
    #[case("/a;b,c=d")]
    #[case("/~user/-._")]
    #[case("http://example.com:8080/a/b?c=d&e=f")]
    #[case("*")]
    #[case("example.com:443")]
    fn the_uri_alphabet_is_not_narrowed(#[case] uri: &str) {
        assert_eq!(judge(uri, "HTTP/1.1"), None);
    }

    /// One rule, three versions: what the field holds differs, what derives from
    /// the productions does not.
    #[rstest]
    #[case("HTTP/1.1")]
    #[case("HTTP/1.0")]
    #[case("HTTP/2.0")]
    #[case("HTTP/3")]
    fn no_version_is_exempt(#[case] version: &str) {
        assert!(judge("https://example.com/a%2", version).is_some());
    }

    /// The finding names the request target and not the request-line's
    /// request-target, because two of the three versions have no request-line.
    #[test]
    fn the_finding_names_the_construct_every_version_has() {
        let msg = judge("https://example.com/a%2", "HTTP/3").expect("must be reported");
        assert!(msg.starts_with("Request target "), "{msg}");
        assert!(!msg.contains("request-target"), "{msg}");
    }

    /// A finding has to print the target it is about, and printing it must not
    /// corrupt the message.
    #[test]
    fn the_target_is_shown_and_escaped() {
        let msg = judge("/a\rb%", "HTTP/1.1").expect("must be reported");
        assert!(msg.contains("/a\\rb%"), "{msg}");
        assert!(!msg.contains('\r'), "{msg}");
    }

    /// A target with both defects reports the percent-encoding: a character the
    /// alphabet lacks is the same finding one step further out, and the triplet
    /// is the more specific reading of the value.
    #[test]
    fn the_triplet_is_read_before_the_alphabet() {
        let msg = judge("/a{b}%2", "HTTP/1.1").expect("must be reported");
        assert!(msg.contains("Percent-encoding incomplete"), "{msg}");
    }

    /// The dependency on the capture path, pinned: `http::Uri` is what the proxy
    /// builds `tx.request.uri` from, and a malformed triplet passes through it
    /// unchanged -- which is why these findings are reachable on live traffic
    /// and not only in a capture file read back through `lint`. The characters
    /// it refuses are the ones `description()` lists as reachable only that way;
    /// when this test fails, that paragraph is what has gone stale.
    #[test]
    fn the_capture_path_does_not_normalise_the_value_away() {
        for reaches_a_capture in [
            "/incomplete%2",
            "/endswith%",
            "/bad%2Gchar",
            "/bad%zz",
            "/path/{id}",
            "/a|b",
            "/a\\b",
            "/a^b",
            "/a\"b",
            "/caf\u{e9}/x",
        ] {
            let parsed: hyper::Uri = reaches_a_capture
                .parse()
                .expect("the parser on the capture path admits this");
            assert_eq!(parsed.to_string(), reaches_a_capture);
        }
        for refused_before_a_capture in ["/a<b>c", "/a`b", "/pa th"] {
            assert!(refused_before_a_capture.parse::<hyper::Uri>().is_err());
        }
    }

    #[test]
    fn scope_is_client() {
        let rule = ClientRequestUriPercentEncodingValid;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Client);
    }
}
