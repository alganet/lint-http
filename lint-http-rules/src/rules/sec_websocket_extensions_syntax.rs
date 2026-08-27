// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::helpers::headers::{
    combined_field_value_as_written, quoted_string_interior, quoting_is_balanced, shown_in_finding,
    split_commas_respecting_quotes, split_semicolons_respecting_quotes, trim_ows,
    unescape_quoted_string,
};
use crate::helpers::token::find_invalid_token_char;
use crate::lint::Violation;
use crate::rules::Rule;

pub struct SecWebsocketExtensionsSyntax;

/// Why one `extension` derives from no production.
///
/// The member arrives already cut from the list and trimmed of the whitespace
/// RFC 2616's implied `*LWS` rule permits around the comma. Its parts are read
/// in the order § 9.1 prints them, so the octet that stopped each is reported
/// against the part it interrupted.
///
/// **The parameter walk is written here rather than shared, and the reason is
/// the notation.** `helpers::headers::parameters` reads RFC 9110 § 5.6.6's
/// `parameters`, whose Note forbids whitespace beside the `=` and whose
/// `parameter` requires a value. This grammar is RFC 2616's: the value is
/// optional (`token [ "=" (token | quoted-string) ]`), and implied `*LWS`
/// *permits* whitespace between any two adjacent words and between a word and a
/// separator — the exact axis `BWS` has been the tell for, answered the other
/// way. Second field in this tree whose parameters come out of a 1997 document,
/// after `Keep-Alive`.
///
/// cite(RFC 6455 § 9.1, label: Sec-WebSocket-Extensions grammar): "Sec-WebSocket-Extensions = extension-list extension-list = 1#extension extension = extension-token *( ";" extension-param ) extension-token = registered-token registered-token = token extension-param = token [ "=" (token | quoted-string) ]"
/// cite(RFC 2616 § 2.1): "Except where noted otherwise, linear white space (LWS) can be included between any two adjacent words (token or quoted-string), and between adjacent words and separators, without changing the interpretation of a field."
fn extension_defect(member: &str) -> Option<String> {
    let mut parts = split_semicolons_respecting_quotes(member).into_iter();
    let token = parts.next().unwrap_or("");

    // `extension-token` is `registered-token`, which is `token`. RFC 2616's
    // `token` and RFC 9110's derive the same character set -- 2616 subtracts its
    // separators and CTLs from CHAR, and what is left is `tchar` -- so the
    // shared reader answers this, and only the *notation* around it differs.
    //
    // cite(RFC 6455 § 9.1): "Any extension-token used MUST be a registered token (see Section 11.4)."
    if token.is_empty() {
        return Some(format!(
            "member '{}' names no extension: an extension is an extension-token, which is a token \
             of at least one character, optionally followed by \";\"-separated parameters",
            shown_in_finding(member)
        ));
    }
    if let Some(c) = find_invalid_token_char(token) {
        return Some(format!(
            "member '{}' has an extension-token holding '{}'; an extension-token is a token",
            shown_in_finding(member),
            c.escape_debug()
        ));
    }

    for param in parts {
        // The `*( ";" extension-param )` group repeats a *parameter*, and no
        // sentence of this grammar makes one of them null. RFC 2616's
        // null-element permission is the `#rule`'s, and the `#rule` here is the
        // comma-separated list of extensions above.
        if param.is_empty() {
            return Some(format!(
                "member '{}' has an empty parameter: every \";\" in an extension is followed by an \
                 extension-param, which begins with a token",
                shown_in_finding(member)
            ));
        }

        // The `=` is optional, and where it is absent the parameter is a bare
        // token -- which is what `permessage-deflate`'s `client_no_context_takeover`
        // is. Splitting on the first one is the production's own reading: a
        // second `=` is inside the value, where a `token` does not admit it and
        // a `quoted-string` does.
        let (name, value) = match param.split_once('=') {
            Some((name, value)) => (trim_ows(name), Some(trim_ows(value))),
            None => (param, None),
        };

        if name.is_empty() {
            return Some(format!(
                "member '{}' has a parameter with no name before its \"=\"; an extension-param \
                 begins with a token",
                shown_in_finding(member)
            ));
        }
        if let Some(c) = find_invalid_token_char(name) {
            return Some(format!(
                "member '{}' has a parameter name holding '{}'; a parameter name is a token",
                shown_in_finding(member),
                c.escape_debug()
            ));
        }

        let Some(value) = value else {
            continue;
        };

        // The alternation, and the arm is chosen by the first octet: a value
        // opening with DQUOTE is being written as a `quoted-string` and is
        // measured as one, so `="a` is an unterminated quoted-string rather than
        // a token holding a DQUOTE.
        if value.starts_with('"') {
            // `unescape_quoted_string` answers both halves in one pass -- the
            // value is a well-formed `quoted-string`, and what it unescapes to
            // -- so an unterminated one and an unquotable octet arrive as the
            // same `Err` and are worded apart by what the caller knows: this
            // arm was entered because the value opened with a DQUOTE.
            //
            // The trailing comment of the production is a requirement about the
            // *unescaped* value, so the check runs after unescaping and not on
            // the octets as written: `"a\\b"` unescapes to `a\b`, whose
            // backslash no token admits.
            //
            // cite(RFC 6455 § 9.1, label: quoted-string parameter note): ";When using the quoted-string syntax variant, the value ;after quoted-string unescaping MUST conform to the ;'token' ABNF."
            let unescaped = match unescape_quoted_string(value) {
                Ok(unescaped) => unescaped,
                Err(_) if quoted_string_interior(value).is_none() => {
                    return Some(format!(
                        "member '{}' has a parameter value opening with a quotation mark that \
                         never closes",
                        shown_in_finding(member)
                    ))
                }
                Err(e) => {
                    return Some(format!(
                        "member '{}' has a parameter whose quoted-string value is malformed: {e}",
                        shown_in_finding(member)
                    ))
                }
            };
            if unescaped.is_empty() {
                return Some(format!(
                    "member '{}' has a parameter whose quoted-string value unescapes to nothing, \
                     and the value after unescaping must conform to the token ABNF, which is at \
                     least one character",
                    shown_in_finding(member)
                ));
            }
            if let Some(c) = find_invalid_token_char(&unescaped) {
                return Some(format!(
                    "member '{}' has a parameter whose quoted-string value unescapes to '{}', \
                     holding '{}'; the value after unescaping must conform to the token ABNF",
                    shown_in_finding(member),
                    shown_in_finding(&unescaped),
                    c.escape_debug()
                ));
            }
            continue;
        }

        if value.is_empty() {
            return Some(format!(
                "member '{}' has a parameter whose \"=\" is followed by no value; the alternation \
                 is a token or a quoted-string, and neither derives the empty string",
                shown_in_finding(member)
            ));
        }
        if let Some(c) = find_invalid_token_char(value) {
            return Some(format!(
                "member '{}' has a parameter value holding '{}'; an unquoted value is a token",
                shown_in_finding(member),
                c.escape_debug()
            ));
        }
    }

    None
}

impl SecWebsocketExtensionsSyntax {
    /// One field section's `Sec-WebSocket-Extensions`, measured against the
    /// grammar § 9.1 prints.
    ///
    /// Read as the sender wrote it, one `char` per octet: `to_str` would turn a
    /// value carrying `obs-text` into a message with no such field, and
    /// `obs-text` is exactly what neither `token` nor RFC 2616's `qdtext`
    /// admits here.
    ///
    /// **The list is RFC 2616's `#rule`, and that is not RFC 9110's.** Null
    /// elements are *allowed* — `foo,,bar` is two extensions and conforms —
    /// where § 5.6.1.1 makes an empty member a sender's MUST NOT for every
    /// field this catalogue otherwise reads. What `1#` does require is one
    /// non-null element, so a value that is only commas and whitespace is the
    /// finding instead. **Reading this field from RFC 9110's list rules would
    /// report a conforming value and pass a malformed one**, in that order.
    ///
    /// cite(RFC 6455 § 9.1): "Note that this section is using ABNF syntax/rules from [RFC2616], including the "implied *LWS rule"."
    /// cite(RFC 2616 § 2.1): "Wherever this construct is used, null elements are allowed, but do not contribute to the count of elements present."
    /// cite(RFC 2616 § 2.1): "Therefore, where at least one element is required, at least one non-null element MUST be present."
    fn defect(headers: &hyper::HeaderMap, direction: &str) -> Option<String> {
        let value = combined_field_value_as_written(headers, "sec-websocket-extensions")?;

        // Asked before the split, because a quote that never closes makes every
        // separator after it data: the member list this walk would judge is not
        // the list the sender wrote, and a finding about a member it invented
        // would name the wrong octet.
        if !quoting_is_balanced(&value) {
            return Some(format!(
                "{direction} Sec-WebSocket-Extensions has a quotation mark that never closes: \
                 '{}'",
                shown_in_finding(&value)
            ));
        }

        let members = split_commas_respecting_quotes(&value);

        // cite(RFC 6455 § 9.1): "If a value is received by either the client or the server during negotiation that does not conform to the ABNF below, the recipient of such malformed data MUST immediately _Fail the WebSocket Connection_."
        if members.iter().all(|m| m.is_empty()) {
            return Some(format!(
                "{direction} Sec-WebSocket-Extensions names no extension: '{}'. The field is \
                 `1#extension`, and RFC 2616's list construct — the one this grammar uses — allows \
                 null elements but requires at least one that is not",
                shown_in_finding(&value)
            ));
        }

        for member in members {
            // The null element the `#rule` permits, and the one place this field
            // is more permissive than every other list in this catalogue.
            if member.is_empty() {
                continue;
            }
            if let Some(defect) = extension_defect(member) {
                return Some(format!("{direction} Sec-WebSocket-Extensions {defect}"));
            }
        }

        None
    }
}

impl Rule for SecWebsocketExtensionsSyntax {
    fn id(&self) -> &'static str {
        "sec_websocket_extensions_syntax"
    }

    /// Both directions carry the field and both are measured against the same
    /// production: § 9.1 gives the client's offer and the server's answer one
    /// grammar, and its malformed-value MUST names *"either the client or the
    /// server"*.
    ///
    /// cite(RFC 6455 § 9.1): "A client requests extensions by including a |Sec-WebSocket-Extensions| header field, which follows the normal rules for HTTP header fields (see [RFC2616], Section 4.2) and the value of the header field is defined by the following ABNF [RFC2616]."
    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
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
            let message = Self::defect(&tx.request.headers, "Request").or_else(|| {
                let resp = tx.response.as_ref()?;
                Self::defect(&resp.headers, "Response")
            })?;

            Some(self.violation(ctx.severity, message))
        };
        Vec::from_iter(finding())
    }

    fn description(&self) -> &'static str {
        "Parses `Sec-WebSocket-Extensions` — a request's and a response's — against the grammar RFC 6455 §9.1 prints: `extension-list = 1#extension`, `extension = extension-token *( \";\" extension-param )`, `extension-token = registered-token = token`, and `extension-param = token [ \"=\" (token | quoted-string) ]`. §9.1 is also what makes a malformed value a finding rather than a note: *If a value is received by either the client or the server during negotiation that does not conform to the ABNF below, the recipient of such malformed data MUST immediately _Fail the WebSocket Connection_.*\n\n**The notation is RFC 2616's, and that changes two answers.** §9.1 says so in as many words — *this section is using ABNF syntax/rules from [RFC2616], including the \"implied *LWS rule\"* — and the current specification naming the obsolete one is what makes citing it right rather than stale.\n\n- **Null list elements are allowed.** RFC 2616 §2.1: *Wherever this construct is used, null elements are allowed, but do not contribute to the count of elements present.* So `foo,,bar` is two extensions and conforms — where RFC 9110 §5.6.1.1 makes an empty member a sender's MUST NOT for every other list-based field in this catalogue. What `1#` does require is that *at least one non-null element MUST be present*, so a value that is nothing but commas and whitespace is the finding instead. Reading this field from RFC 9110's list rules would report a conforming value and pass a malformed one, in that order.\n- **Whitespace may sit beside the delimiters.** Implied `*LWS` puts it *between any two adjacent words … and between adjacent words and separators*, so `permessage-deflate ; client_max_window_bits = 15` conforms. RFC 9110 §5.6.6's Note forbids exactly that around a parameter's `=`, which is why this rule writes its own parameter walk instead of calling the shared one — the same reasoning as `Keep-Alive`, the other field in this tree whose parameters come out of a 1997 document, reached in the opposite direction.\n\n**What a member is measured for.** Its `extension-token` is a token of at least one character; each `;` is followed by a parameter whose name is a token; a parameter's value is optional, and when present is a token or a quoted-string. A quoted-string value carries the production's own trailing requirement — *When using the quoted-string syntax variant, the value after quoted-string unescaping MUST conform to the 'token' ABNF* — so `x=\"a b\"` is reported for the space it unescapes to, and `x=\"\"` for unescaping to nothing.\n\n**Not reported: whether the extension-token is registered.** §9.1 says *Any extension-token used MUST be a registered token (see Section 11.4)*, and §11.4's policy is First Come First Served — a name registered tomorrow conforms today, so an allowlist would report senders for the registry's latency and a config key would ask an operator to maintain one. Nor is *The parameters supplied with any given extension MUST be defined for that extension* enforced: which parameters `permessage-deflate` defines is RFC 7692's question, and answering it here would mean this rule reading that document for this one.\n\n**Not reported: whether the response's extensions were offered.** That comparison is `websocket_handshake_valid`'s, which needs both halves of one exchange; this rule measures each field section on its own. The value also decides `websocket_frame_rsv_bits`'s verdicts, since a `101` accepting an extension is what licenses a non-zero reserved bit — which is a reason to measure this field, not a claim that the frame rule reads it twice.\n\nScope: this rule reads header sections — a request's and a response's — and each finding names which. Where the field appears on several lines in one section they are one value (§5.2), which §9.1 states for this field by name and demonstrates with a worked example. A value carrying an octet outside US-ASCII is measured rather than skipped: it reaches the production that excludes it and is reported there. The member split is quote-aware, because a `quoted-string` parameter value may hold a comma; a value whose quoting never closes is reported as that, before any member is judged, since every separator after an unclosed quote is data."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 6455",
                section: Some("9.1"),
                url: "https://www.rfc-editor.org/rfc/rfc6455.html#section-9.1",
                note: "Negotiating Extensions — the grammar, the MUST that makes a non-conforming \
                       value a failure of the connection, the note that the notation is RFC \
                       2616's, and the requirement on a quoted-string value after unescaping",
            },
            crate::rules::SpecRef {
                spec: "RFC 2616",
                section: Some("2.1"),
                url: "https://www.rfc-editor.org/rfc/rfc2616.html#section-2.1",
                note: "Augmented BNF — the notation §9.1 imports by name: the `#rule` whose null \
                       elements are allowed (RFC 9110 §5.6.1.1 forbids them) and the implied \
                       *LWS rule that permits whitespace beside the separators. Obsolete and \
                       correct: the current document is what sends the reader here",
            },
            crate::rules::SpecRef {
                spec: "RFC 6455",
                section: Some("11.4"),
                url: "https://www.rfc-editor.org/rfc/rfc6455.html#section-11.4",
                note: "WebSocket Extension Name Registry — First Come First Served, which is why \
                       no extension-token is compared against a list here",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("§9.1's own worked example, on the two lines it prints it as"),
                snippet: "GET /chat HTTP/1.1\nHost: example.com\nSec-WebSocket-Extensions: foo\nSec-WebSocket-Extensions: bar; baz=2",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("Implied *LWS: whitespace beside the separators changes nothing"),
                snippet: "GET /chat HTTP/1.1\nHost: example.com\nSec-WebSocket-Extensions: permessage-deflate ; client_max_window_bits = 15",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("A null element — RFC 2616's list construct allows it"),
                snippet: "GET /chat HTTP/1.1\nHost: example.com\nSec-WebSocket-Extensions: foo,,bar",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("`1#extension` needs one element that is not null"),
                snippet: "GET /chat HTTP/1.1\nHost: example.com\nSec-WebSocket-Extensions: ,",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("`/` is a separator, so the extension-token is not a token"),
                snippet: "GET /chat HTTP/1.1\nHost: example.com\nSec-WebSocket-Extensions: foo/bar",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("The value after unescaping must conform to the token ABNF"),
                snippet: "GET /chat HTTP/1.1\nHost: example.com\nSec-WebSocket-Extensions: foo; bar=\"a b\"",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &SecWebsocketExtensionsSyntax;

#[cfg(test)]
mod tests {
    use super::*;

    use hyper::header::HeaderValue;
    use rstest::rstest;

    #[derive(Clone, Copy, Debug)]
    enum Section {
        Request,
        Response,
    }

    /// Every fixture is built here, from raw octets and from a list of lines:
    /// §9.1 prints its own example as two field lines that are one list, and a
    /// value carrying `obs-text` is not a string a Rust source file can stand
    /// in for.
    fn extensions(section: Section, lines: &[&[u8]]) -> Option<Violation> {
        let rule = SecWebsocketExtensionsSyntax;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(101, &[]);
        let mut hm = hyper::HeaderMap::new();
        for line in lines {
            hm.append(
                hyper::header::HeaderName::from_static("sec-websocket-extensions"),
                HeaderValue::from_bytes(line).expect("field value"),
            );
        }
        match section {
            Section::Request => tx.request.headers = hm,
            Section::Response => tx.response.as_mut().expect("response").headers = hm,
        }
        crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
    }

    #[rstest]
    #[case("foo")]
    #[case("permessage-deflate")]
    #[case("foo, bar; baz=2")]
    #[case("permessage-deflate; client_no_context_takeover")]
    #[case("permessage-deflate ; client_max_window_bits = 15")]
    #[case("foo; bar=\"baz\"")]
    // The null elements RFC 2616's `#rule` allows, in the three places they go.
    #[case("foo,,bar")]
    #[case(",foo")]
    #[case("foo,")]
    #[case("foo, , bar")]
    fn a_conforming_value_is_not_a_finding(
        #[case] value: &str,
        #[values(Section::Request, Section::Response)] section: Section,
    ) {
        let v = extensions(section, &[value.as_bytes()]);
        assert!(v.is_none(), "{value:?}: {v:?}");
    }

    /// §9.1's own worked example, in both spellings it says are equivalent.
    #[test]
    fn the_sections_own_example_is_one_list_however_many_lines_carry_it() {
        assert!(extensions(Section::Request, &[b"foo" as &[u8], b"bar; baz=2"]).is_none());
        assert!(extensions(Section::Request, &[b"foo, bar; baz=2"]).is_none());
    }

    /// `1#extension` requires one element that is not null, and that is the one
    /// thing RFC 2616's list construct is stricter about than it looks.
    #[rstest]
    #[case(b"")]
    #[case(b",")]
    #[case(b" , ")]
    #[case(b",,,")]
    fn a_list_of_only_null_elements_names_no_extension(
        #[case] value: &[u8],
        #[values(Section::Request, Section::Response)] section: Section,
    ) {
        let v = extensions(section, &[value]).expect("violation");
        assert!(v.message.contains("names no extension"), "{}", v.message);
    }

    #[rstest]
    #[case(b"foo/bar", "extension-token holding '/'")]
    #[case(b"foo bar", "extension-token holding ' '")]
    #[case(b"fo\xe9o", "extension-token holding")]
    #[case(b";foo", "names no extension")]
    #[case(b"foo;", "empty parameter")]
    #[case(b"foo; ;bar", "empty parameter")]
    #[case(b"foo; =2", "no name before")]
    #[case(b"foo; ba/r=2", "parameter name holding '/'")]
    #[case(b"foo; bar=", "followed by no value")]
    #[case(b"foo; bar=a/b", "parameter value holding '/'")]
    #[case(b"foo; bar=\"a b\"", "unescapes to 'a b', holding ' '")]
    #[case(b"foo; bar=\"\"", "unescapes to nothing")]
    #[case(b"foo; bar=\"a", "never closes")]
    fn a_member_deriving_from_no_extension_is_reported_against_the_part_that_stopped(
        #[case] value: &[u8],
        #[case] expected: &str,
    ) {
        let v = extensions(Section::Request, &[value]).expect("violation");
        assert!(v.message.contains(expected), "{}", v.message);
    }

    /// The quoted-string requirement is about the value *after* unescaping, so
    /// an escaped character that is a token character conforms and one that is
    /// not does not — which the octets as written cannot tell apart.
    #[test]
    fn the_quoted_string_requirement_is_read_after_unescaping() {
        assert!(extensions(Section::Request, &[b"foo; bar=\"a\\bc\""]).is_none());
        let v = extensions(Section::Request, &[b"foo; bar=\"a\\\\c\""]).expect("violation");
        assert!(v.message.contains("unescapes to"), "{}", v.message);
    }

    /// A comma inside a quoted-string is data, so the split has to be
    /// quote-aware: read naively this is two members and the first is malformed.
    #[test]
    fn a_comma_inside_a_quoted_string_is_not_a_separator() {
        assert!(extensions(Section::Request, &[b"foo; bar=\"a\", baz"]).is_none());
    }

    /// And a quote that never closes is reported as that, before any member is
    /// judged: every separator after it is data, so the members a walk would
    /// find are not the ones the sender wrote.
    #[test]
    fn an_unbalanced_quote_is_reported_before_the_members_are_judged() {
        let v = extensions(Section::Request, &[b"foo; bar=\"a, baz"]).expect("violation");
        assert!(
            v.message.contains("quotation mark that never closes"),
            "{}",
            v.message
        );
    }

    /// The finding names the section it came from.
    #[rstest]
    #[case(Section::Request, "Request Sec-WebSocket-Extensions")]
    #[case(Section::Response, "Response Sec-WebSocket-Extensions")]
    fn the_finding_names_the_direction(#[case] section: Section, #[case] expected: &str) {
        let v = extensions(section, &[b"foo/bar"]).expect("violation");
        assert!(v.message.starts_with(expected), "{}", v.message);
    }

    #[test]
    fn a_message_with_no_such_field_is_not_measured() {
        assert!(extensions(Section::Request, &[]).is_none());
    }

    /// Every published snippet, run through the rule it is published on.
    #[test]
    fn published_examples_agree_with_the_rule() {
        use crate::rules::{Compliance, Rule as _};
        let rule = SecWebsocketExtensionsSyntax;
        for ex in rule.examples() {
            let lines: Vec<&[u8]> = ex
                .snippet
                .lines()
                .filter_map(|l| l.strip_prefix("Sec-WebSocket-Extensions:"))
                .map(|v| v.strip_prefix(' ').unwrap_or(v).as_bytes())
                .collect();
            assert!(
                !lines.is_empty(),
                "example carries no field: {}",
                ex.snippet
            );
            let v = extensions(Section::Request, &lines);
            match ex.compliance {
                Compliance::Compliant => assert!(v.is_none(), "{}: {v:?}", ex.snippet),
                Compliance::NonCompliant => assert!(v.is_some(), "{}", ex.snippet),
            }
        }
    }

    #[test]
    fn scope_is_both() {
        use crate::rules::Rule as _;
        assert_eq!(
            SecWebsocketExtensionsSyntax.scope(),
            crate::rules::RuleScope::Both
        );
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "sec_websocket_extensions_syntax");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
