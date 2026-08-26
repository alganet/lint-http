// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct RequestTargetNoFragment;

impl Rule for RequestTargetNoFragment {
    fn id(&self) -> &'static str {
        "request_target_no_fragment"
    }

    /// The sentence read here is addressed to the client that resolved a
    /// reference into a target URI and sent its components, so the rule has to
    /// run on a capture whose upstream never answered as well as on a complete
    /// exchange. `Server` means "skip when there is no response", which would
    /// skip exactly the request-only lint -- and the fragment was already on
    /// the wire when the request was sent.
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
        // target whatever the major version puts them in.
        // cite(RFC 9110 § 7.1): "For historical reasons, the parsed target URI components, collectively referred to as the "request target", are sent within the message control data and the Host header field"
        let target = tx.request.uri.as_str();

        // One character opens the component and the end of the value closes it,
        // so the first number sign is the whole detection and everything from it
        // onwards is the fragment. A number sign that is *data* rather than the
        // delimiter arrives percent-encoded and this test does not see it, which
        // is the second sentence: `/a%23b` is a path segment containing a number
        // sign and is nobody's finding.
        // cite(RFC 3986 § 3.5): "A fragment identifier component is indicated by the presence of a number sign ("#") character and terminated by the end of the URI."
        // cite(RFC 3986 § 2.2): "If data for a URI component would conflict with a reserved character's purpose as a delimiter, then the conflicting data must be percent-encoded before the URI is formed."
        let hash = target.find('#')?;

        // Read after the finding is certain: parsing the config is several map
        // probes and a hash of the rule id, where the test above is one scan of
        // a string the transaction already holds, and every return above this
        // one ends the rule.
        let severity = crate::rules::parse_rule_config(cfg, self.id())
            .ok()?
            .severity;

        // A target read back from a capture can hold characters that print as
        // nothing or, worse, print as something else: an escape sequence in a
        // finding is a finding nobody can read.
        let shown = crate::helpers::headers::shown_in_finding(target);
        let fragment = crate::helpers::headers::shown_in_finding(&target[hash..]);

        // Which productions the components had to derive from is the major
        // version's question, and the answer is the same on both sides -- so the
        // finding is version-independent and only its last sentence is not.
        //
        // HTTP/1.x sends them on a request-line, where `absolute-form` is
        // `absolute-URI`: the `URI` production with `[ "#" fragment ]` dropped,
        // which is § 4.2.5's "specific rule that excludes fragments" in the
        // clearest form the generic syntax has. The other three forms are an
        // absolute path with an optional query, a host and a port, and one
        // character.
        //
        // HTTP/2 and HTTP/3 have no request-line at all: the components arrive
        // as pseudo-header fields, and `:path` is the same absolute path and
        // query. A version this proxy does not record gets no clause rather than
        // a guess -- the sentences above it hold on every version.
        //
        // All three arms read the major digit, which is the digit the first
        // sentence below gives the meaning to, so HTTP/1.0 and HTTP/1.1 are one
        // case and `HTTP/1x` is nobody's version. Only the first arm is reading
        // something a message carried; the other two versions have no
        // `HTTP-version` field, and what a capture records for them is the
        // protocol version their own specifications state in words, `HTTP/2.0`
        // and `HTTP/3.0` (RFC 9113 § 8.3.1, RFC 9114 § 4.3.1). Until 2026-08-03
        // these were two `starts_with` hand copies of the production, one of
        // which admitted `HTTP/2x`; `http_version` owns it now.
        // cite(RFC 9110 § 2.5): "The first digit (major version) indicates the messaging syntax"
        // cite(RFC 9112 § 2.3, label: HTTP-version): "HTTP-version  = HTTP-name "/" DIGIT "." DIGIT"
        // cite(RFC 9110 § 4.2.5): "Some protocol elements that refer to a URI allow inclusion of a fragment, while others do not."
        // cite(RFC 9110 § 4.2.5): "They are distinguished by use of the ABNF rule for elements where fragment is allowed; otherwise, a specific rule that excludes fragments is used."
        // cite(RFC 3986 § 3, label: URI): "URI         = scheme ":" hier-part [ "?" query ] [ "#" fragment ]"
        // cite(RFC 3986 § 4.3, label: absolute-URI): "absolute-URI  = scheme ":" hier-part [ "?" query ]"
        // cite(RFC 9112 § 3.2.2, label: absolute-form): "absolute-form  = absolute-URI"
        // cite(RFC 9112 § 3.2.1, label: origin-form): "origin-form    = absolute-path [ "?" query ]"
        // cite(RFC 9113 § 8.3.1): "The ":path" pseudo-header field includes the path and query parts of the target URI"
        // cite(RFC 9114 § 4.3.1): "Contains the path and query parts of the target URI"
        let carried_in = match crate::http_version::major(&tx.request.version) {
            Some(1) => " No form of an HTTP/1.x request-line's request-target derives it: absolute-form is an absolute-URI, which is the URI production with the fragment component dropped, and the other three are an absolute path with an optional query, a host and a port, and the asterisk.",
            Some(2 | 3) => " This version sends no request-line: the components arrive as pseudo-header fields, and ':path' carries the path and query parts of the target URI, which is where the fragment is not.",
            _ => "",
        };

        // The requirement is the grammar's, so the sentence that makes a value
        // matching no production a finding is § 2.2's -- and reaching it from an
        // HTTP/1.1 production needs § 1.1, which puts this document's conformance
        // criteria in the other one.
        // cite(RFC 9110 § 2.2): "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules."
        // cite(RFC 9112 § 1.1): "Conformance criteria and considerations regarding error handling are defined in Section 2 of [HTTP]."
        // cite(RFC 9110 § 7.1): "A URI reference is resolved to its absolute form in order to obtain the "target URI"."
        // cite(RFC 9110 § 7.1): "The target URI excludes the reference's fragment component, if any, since fragment identifiers are reserved for client-side processing"
        // cite(RFC 3986 § 3.5): "the fragment identifier is separated from the rest of the URI prior to a dereference, and thus the identifying information within the fragment itself is dereferenced solely by the user agent, regardless of the URI scheme"
        Some(Violation {
            rule: self.id().into(),
            severity,
            message: format!(
                "Request target '{shown}' carries a fragment identifier, '{fragment}' -- \
                 the number sign and everything after it to the end of the value. A client \
                 resolves the reference it started from into a target URI that excludes that \
                 reference's fragment, because a fragment is separated from the rest of the URI \
                 before any dereference and is resolved solely by the user agent: the recipient \
                 of this message is being sent a component addressed to the sender.{carried_in}"
            ),
        })
    }

    fn description(&self) -> &'static str {
        "Reports a request whose target carries a fragment identifier — a number sign (`#`) and everything after it to the end of the value (RFC 3986 §3.5).\n\n**A client has no fragment to send.** It resolves the URI reference it started from into the target URI, and that target URI *\"excludes the reference's fragment component, if any, since fragment identifiers are reserved for client-side processing\"* (RFC 9110 §7.1). RFC 3986 §3.5 says why: the fragment is separated from the rest of the URI before a dereference, and the information in it is dereferenced solely by the user agent, whatever the scheme. A recipient handed one has been sent a component addressed to the sender.\n\n**Which protocol elements admit a fragment is decided by their ABNF, and no request target's does.** RFC 9110 §4.2.5 states the rule — elements that do not allow one use *\"a specific rule that excludes fragments\"* — and the generic syntax has the clearest example of such a rule: `absolute-URI` is `scheme \":\" hier-part [ \"?\" query ]`, which is the `URI` production with `[ \"#\" fragment ]` dropped. HTTP/1.1's `absolute-form` is exactly that (RFC 9112 §3.2.2); `origin-form` is an absolute path and an optional query; a CONNECT's target is a host and a port; the asterisk is one character. HTTP/2 and HTTP/3 send no request-line at all, and their `:path` is the path and query parts of the target URI (RFC 9113 §8.3.1, RFC 9114 §4.3.1) — the same two productions. So the finding rests on RFC 9110 §2.2's *\"A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules\"*, and RFC 9112 §1.1 is what carries that conformance criterion to an HTTP/1.1 production.\n\nThe rule is therefore **not version-gated**: only the last sentence of the finding differs, naming the request-line or the pseudo-header fields the fragment rode in on.\n\n**A percent-encoded number sign is data and is not reported.** `%23` is what RFC 3986 §2.2 asks for when data would conflict with a reserved character's purpose as a delimiter, so `/a%23b` is a path segment containing a number sign and is clean. An empty fragment (`/a#`) is reported: the component is present, and the number sign is what says so.\n\n**What this rule cannot see: anything this proxy captured itself.** Both transports build the recorded target from a parsed URI, and that parse truncates the value at the first number sign before a transaction exists — the fragment is gone before any rule runs, and it does not reach the upstream either. The finding is reachable when a capture recorded elsewhere is read back through the `lint` subcommand's JSONL file.\n\n**What this rule does not decide.** Which of the four forms a request-target derives from, and whether the method may use that form, is `request_target_form_valid`; whether a percent-encoded triplet is well formed is `request_uri_percent_encoding_valid`. Whether a *field* carrying a URI reference may hold a fragment is that field's own question and not this one's — `Location = URI-reference` admits one (RFC 9110 §10.2.2), and `Referer` forbids one (§10.1.3)."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 3986",
                section: Some("3.5"),
                url: "https://www.rfc-editor.org/rfc/rfc3986.html#section-3.5",
                note: "Fragment: indicated by a number sign and terminated by the end of the URI; separated from the rest of the URI before a dereference and resolved solely by the user agent",
            },
            crate::rules::SpecRef {
                spec: "RFC 3986",
                section: Some("2.2"),
                url: "https://www.rfc-editor.org/rfc/rfc3986.html#section-2.2",
                note: "Reserved characters: data that would conflict with a delimiter's purpose is percent-encoded before the URI is formed, which is why %23 is not this rule's finding",
            },
            crate::rules::SpecRef {
                spec: "RFC 3986",
                section: Some("4.3"),
                url: "https://www.rfc-editor.org/rfc/rfc3986.html#section-4.3",
                note: "absolute-URI: the URI production with the fragment component dropped",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("7.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-7.1",
                note: "Determining the Target Resource: the target URI excludes the reference's fragment, and the components sent are collectively the request target on every major version",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("4.2.5"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-4.2.5",
                note: "http(s) references with fragment identifiers: whether an element admits a fragment is decided by the ABNF rule it uses",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("2.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-2.2",
                note: "The sender MUST NOT that a value matching no production breaks; RFC 9112 §1.1 carries it to the HTTP/1.1 productions",
            },
            crate::rules::SpecRef {
                spec: "RFC 9112",
                section: Some("3.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2",
                note: "Request Target: the four forms an HTTP/1.1 request-line may carry, none of which derives a fragment",
            },
            crate::rules::SpecRef {
                spec: "RFC 9113",
                section: Some("8.3.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9113.html#section-8.3.1",
                note: "HTTP/2 request pseudo-header fields: :path is the path and query parts of the target URI",
            },
            crate::rules::SpecRef {
                spec: "RFC 9114",
                section: Some("4.3.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9114.html#section-4.3.1",
                note: "HTTP/3 request pseudo-header fields: the same two parts of the target URI",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("Request"),
                snippet: "GET /index.html HTTP/1.1\nHost: example.com",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("Request (a number sign as data, percent-encoded)"),
                snippet: "GET /search?q=C%23 HTTP/1.1\nHost: example.com",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("Request (fragment in origin-form)"),
                snippet: "GET /index.html#section1 HTTP/1.1\nHost: example.com",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("Request (fragment in absolute-form)"),
                snippet: "GET http://example.com/index.html#section1 HTTP/1.1\nHost: example.com",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &RequestTargetNoFragment;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn judge(uri: &str, version: &str) -> Option<Violation> {
        let rule = RequestTargetNoFragment;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.uri = uri.to_string();
        tx.request.version = version.to_string();

        crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_severity(rule.id(), "error"),
        )
    }

    #[rstest]
    #[case("http://example.com/path")]
    #[case("/origin-form")]
    #[case("/origin-form?query")]
    // The delimiter is one character and a percent-encoded one is not it: a
    // path segment may contain a number sign, and this is how it says so.
    #[case("/a%23b")]
    #[case("/search?q=C%23")]
    // Nothing here reads the rest of the target, so the two forms the sibling
    // rule judges are as clean as any other when they carry no number sign.
    #[case("*")]
    #[case("example.com:443")]
    fn no_fragment(#[case] uri: &str) {
        assert!(judge(uri, "HTTP/1.1").is_none());
    }

    #[rstest]
    #[case("http://example.com/path#fragment", "#fragment")]
    #[case("/origin-form#fragment", "#fragment")]
    #[case("/origin-form?query#fragment", "#fragment")]
    // `fragment = *( pchar / "/" / "?" )` derives the empty string, and the
    // component is present because the number sign says it is.
    #[case("/a#", "#")]
    // The component is terminated by the end of the URI, not by a second
    // delimiter, so the whole tail is one fragment.
    #[case("/a#b#c", "#b#c")]
    // A relative reference that is nothing but a fragment. `client_request_
    // target_form_checks` reports the same target for deriving from none of the
    // four forms; that it is not a request-target and that it carries a
    // fragment are two findings, and this rule makes the second.
    #[case("#fragment-only", "#fragment-only")]
    fn fragment_is_named(#[case] uri: &str, #[case] expected: &str) {
        let v = judge(uri, "HTTP/1.1").expect("a fragment is reported");
        assert_eq!(v.rule, "request_target_no_fragment");
        assert!(
            v.message.contains(&format!("'{expected}'")),
            "the fragment itself belongs in the finding: {}",
            v.message
        );
    }

    /// The finding is the same on every version and only its last sentence
    /// moves, because the sentences above it are about the target URI rather
    /// than about a request-line.
    #[rstest]
    #[case("HTTP/1.0", "request-target")]
    #[case("HTTP/1.1", "request-target")]
    #[case("HTTP/2.0", "pseudo-header fields")]
    #[case("HTTP/3.0", "pseudo-header fields")]
    fn the_version_names_what_carried_it(#[case] version: &str, #[case] expected: &str) {
        let v = judge("/a#frag", version).expect("a fragment is reported on every version");
        assert!(v.message.contains(expected), "{}", v.message);
    }

    /// A version this proxy does not record gets the finding and no claim about
    /// how the target reached the wire.
    #[test]
    fn an_unknown_version_is_reported_without_a_carriage_clause() {
        let v = judge("/a#frag", "HTTP/0.9").expect("a fragment is reported");
        assert!(!v.message.contains("request-target"), "{}", v.message);
        assert!(!v.message.contains("pseudo-header"), "{}", v.message);
    }

    /// A target read back from a capture recorded elsewhere can carry anything
    /// UTF-8 admits, and an escape sequence would otherwise be executed by the
    /// terminal the finding is printed to.
    #[test]
    fn a_target_is_escaped_into_the_finding() {
        let v = judge("/\u{1b}[2Ja#\u{1b}[2Jfrag", "HTTP/1.1").expect("a fragment is reported");
        assert!(!v.message.contains('\u{1b}'), "{}", v.message);
        assert!(v.message.contains("\\u{1b}[2Jfrag"), "{}", v.message);
    }

    #[test]
    fn scope_is_client() {
        let rule = RequestTargetNoFragment;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Client);
    }

    /// The boundary `description()` publishes: a capture this proxy recorded
    /// itself cannot reach the check, because both transports build the
    /// recorded target from a parsed URI and that parse drops the fragment
    /// before a transaction exists. Pinned here so the claim fails loudly
    /// rather than quietly becoming false.
    #[test]
    fn the_uri_parse_this_proxy_records_through_drops_the_fragment() {
        for target in ["/index.html#section1", "http://example.com/a#frag"] {
            let parsed: hyper::Uri = target.parse().expect("a URI hyper would accept");
            assert!(
                !parsed.to_string().contains('#'),
                "the recorded target would carry a fragment: {parsed}"
            );
        }
    }
}
