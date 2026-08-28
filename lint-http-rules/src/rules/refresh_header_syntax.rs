// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct RefreshHeaderSyntax;

// This rule holds four of the tree's six WHATWG transcriptions -- the URL
// Standard's *URL code points* and *URL units* below, Infra's *ASCII
// whitespace*, and HTML's *valid non-negative integer* inside
// `refresh_value_error`, whose own two-form authoring requirement is the fifth.
// The sixth is `server_timing_header_syntax`'s *valid floating-point
// number*.
//
// **All six stay private, and the reason is written at `helpers/mod.rs`**: that
// module is shelved by question and never by document, so a `microsyntax.rs`
// collecting these would be filed by publisher. They are two character-class
// sets, a whitespace set, two number productions and a prose shape -- no two the
// same question, none a subroutine of another, one caller each. A second caller
// asking the *same* question is what moves one of them, and reading the same
// document is not that.

/// Whether `c` is one of the code points a URL may be written with.
///
/// Transcribed from the WHATWG URL Standard § 4.3, not from RFC 3986 — the two
/// alphabets differ in both directions, and this is the one HTML's "valid URL
/// string" is defined against. `helpers::uri::find_non_uri_char` is RFC 3986's
/// and would refuse every code point above U+007F, which this one admits.
///
/// The sentence excludes surrogates and noncharacters. Neither is reachable
/// here: the caller's input is isomorphic-decoded field octets, so every code
/// point is U+0000 to U+00FF.
fn is_url_code_point(c: char) -> bool {
    // cite(URL § 4.3): "The URL code points are ASCII alphanumeric, U+0021 (!), U+0024 ($), U+0026 (&), U+0027 ('), U+0028 LEFT PARENTHESIS, U+0029 RIGHT PARENTHESIS, U+002A (*), U+002B (+), U+002C (,), U+002D (-), U+002E (.), U+002F (/), U+003A (:), U+003B (;), U+003D (=), U+003F (?), U+0040 (@), U+005F (_), U+007E (~), and code points in the range U+00A0 to U+10FFFD, inclusive, excluding surrogates and noncharacters."
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            '!' | '$'
                | '&'
                | '\''
                | '('
                | ')'
                | '*'
                | '+'
                | ','
                | '-'
                | '.'
                | '/'
                | ':'
                | ';'
                | '='
                | '?'
                | '@'
                | '_'
                | '~'
        )
        || ('\u{A0}'..='\u{10FFFD}').contains(&c)
}

/// The reason `s` cannot be a *valid URL string*, or `None`.
///
/// This answers the alphabet half of that question and nothing else: whether the
/// components are in a legal order, and whether a host parses, are the URL
/// parser's questions and are not decided here.
///
/// Three ASCII code points that are not URL code points are still admitted,
/// because the grammar spends them as delimiters rather than as data. The two
/// sentences that name them are cited at the exclusion below; no other code
/// point outside the set has one.
fn find_invalid_url_unit(s: &str) -> Option<String> {
    for (i, c) in s.char_indices() {
        if c == '%' {
            // cite(URL § 4.3): "URL units are URL code points and percent-encoded bytes."
            // A percent-encoded byte is `%` and exactly two hex digits, so a `%`
            // that does not open one is the code point itself, unescaped.
            let mut rest = s[i + 1..].chars();
            let two_hex = matches!((rest.next(), rest.next()),
                (Some(a), Some(b)) if a.is_ascii_hexdigit() && b.is_ascii_hexdigit());
            if !two_hex {
                return Some(
                    "has a '%' not followed by two hex digits, so it is not a percent-encoded byte"
                        .into(),
                );
            }
            continue;
        }
        // cite(URL § 4.3): "An absolute-URL-with-fragment string must be an absolute-URL string, optionally followed by U+0023 (#) and a URL-fragment string."
        // cite(URL § 3.4): "A valid host string must be a valid domain string, a valid IPv4-address string, or: U+005B ([), followed by a valid IPv6-address string, followed by U+005D (])."
        // `#`, `[` and `]` are named by the grammar as the delimiters they are.
        if is_url_code_point(c) || matches!(c, '#' | '[' | ']') {
            continue;
        }
        // cite(URL § 1.1): "A code point is found that is not a URL unit."
        return Some(format!("contains {c:?}, which is not a URL unit"));
    }
    None
}

/// Whether `c` is ASCII whitespace, as the WHATWG documents above use the term.
///
/// `char::is_ascii_whitespace` is the same five code points today, and
/// `std_agrees_on_ascii_whitespace` pins that. This exists anyway because the
/// sentence has to have somewhere to attach: a call to std carries no
/// transcription, so there would be nothing for the cite to sit on.
fn is_ascii_whitespace(c: char) -> bool {
    // cite(Infra § 4.6): "ASCII whitespace is U+0009 TAB, U+000A LF, U+000C FF, U+000D CR, or U+0020 SPACE."
    matches!(c, '\t' | '\n' | '\u{C}' | '\r' | ' ')
}

/// The reason `s` is not a conforming `Refresh` value, or `None`.
///
/// `s` is the whole field value, isomorphic-decoded and with HTTP's leading and
/// trailing whitespace already removed. The production is the authoring
/// conformance requirement for the `meta` pragma, which § 7.8 makes this field's
/// too — two forms, and everything else is a finding.
fn refresh_value_error(s: &str) -> Option<String> {
    // cite(HTML Semantics § 4.2.5.3): "For meta elements with an http-equiv attribute in the Refresh state, the content attribute must have a value consisting either of:"
    // cite(HTML Semantics § 4.2.5.3): "just a valid non-negative integer, or"
    // cite(HTML Semantics § 4.2.5.3): "a valid non-negative integer, followed by a U+003B SEMICOLON character (;), followed by one or more ASCII whitespace, followed by a substring that is an ASCII case-insensitive match for the string "URL", followed by a U+003D EQUALS SIGN character (=), followed by a valid URL string"
    // The sentence runs on into the quote clause, which is cited at the check
    // that enforces it below: the trailing `(")` leaves this fragment's
    // quotation marks unpaired, and the cite grammar has no escape for that.
    //
    // The `;` is the only structural delimiter in either form, and the URL runs
    // from `URL=` to the end of the value. So this splits once, at the first
    // `;`, and never again — a `;` or a `,` further along is data inside the URL,
    // which the second form admits.
    let (time, after_semicolon) = match s.find(';') {
        Some(i) => (&s[..i], Some(&s[i + 1..])),
        None => (s, None),
    };

    // cite(HTML Common Microsyntaxes § 2.3.4.2): "A string is a valid non-negative integer if it consists of one or more ASCII digits."
    // One or more ASCII digits and nothing else — no sign, no radix point. This
    // is why the check is not `parse::<u64>()`, which accepts a leading `+`.
    if time.is_empty() || !time.chars().all(|c| c.is_ascii_digit()) {
        return Some(format!(
            "'{time}' is not a valid non-negative integer; the value is a delay in seconds, \
             optionally followed by `; URL=<url>`"
        ));
    }

    // No `;`: the value is the first form, and the first form is complete.
    let after_semicolon = after_semicolon?;

    let after_ws = after_semicolon.trim_start_matches(is_ascii_whitespace);
    if after_ws.is_empty() {
        return Some(
            "the ';' is followed by nothing; the second form is `<seconds>; URL=<url>`".into(),
        );
    }
    if !after_semicolon.starts_with(is_ascii_whitespace) {
        return Some(format!(
            "the ';' is not followed by whitespace; the second form is `<seconds>; URL=<url>`, \
             not `;{after_ws}`"
        ));
    }

    let mut it = after_ws.chars();
    let keyword = (it.next(), it.next(), it.next(), it.next());
    let is_url_eq = matches!(keyword, (Some(u), Some(r), Some(l), Some('='))
        if u.eq_ignore_ascii_case(&'U') && r.eq_ignore_ascii_case(&'R') && l.eq_ignore_ascii_case(&'L'));
    if !is_url_eq {
        return Some(format!(
            "'{after_ws}' is not a `URL=` parameter; `URL` is the only name the second form \
             admits, and no whitespace is permitted around its '='"
        ));
    }

    let url: String = it.collect();
    if url.is_empty() {
        return Some("`URL=` carries no URL".into());
    }
    // cite(HTML Semantics § 4.2.5.3): "that does not start with a literal U+0027 APOSTROPHE (') or U+0022 QUOTATION MARK"
    // The rest of the second form's sentence, above. A quoted URL is not a
    // conforming value even though the processing model reads one, and the
    // reading is why: the closing quote and everything after it are discarded,
    // so a sender who quotes a URL loses whatever followed the second mark.
    // cite(HTML Semantics § 4.2.5.3): "If quote is not the empty string, and there is a code point in urlString equal to quote, then truncate urlString at that code point, so that it and all subsequent code points are removed."
    if url.starts_with('\'') || url.starts_with('"') {
        return Some(format!(
            "the URL {url:?} starts with a quote character, which the value may not do"
        ));
    }
    // cite(URL § 4.3): "A valid URL string must be either a relative-URL-with-fragment string or an absolute-URL-with-fragment string."
    // Relative is a conforming form, which is why nothing here asks for a
    // scheme: `1http://example/` names none and is an ordinary relative path,
    // not a malformed absolute URL.
    find_invalid_url_unit(&url).map(|why| format!("the URL {url:?} {why}"))
}

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const HTML_SPECULATIVE_LOADING_7_8: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "HTML Speculative Loading",
    section: Some("7.8"),
    url: "https://html.spec.whatwg.org/multipage/speculative-loading.html#the-refresh-header",
    note: "The `Refresh` header. Three sentences: it is the `meta` pragma's HTTP equivalent, it takes the same value, and its processing model is elsewhere. It states no requirement of its own",
};
const HTML_SEMANTICS_4_2_5_3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "HTML Semantics",
    section: Some("4.2.5.3"),
    url: "https://html.spec.whatwg.org/multipage/semantics.html#attr-meta-http-equiv-refresh",
    note: "Refresh state: the shared declarative refresh steps, and the authoring conformance requirement this rule enforces — the only sentence in HTML that says what a conforming value looks like",
};
const HTML_DOCUMENT_LIFECYCLE_7_5_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "HTML Document Lifecycle",
    section: Some("7.5.1"),
    url: "https://html.spec.whatwg.org/multipage/document-lifecycle.html#initialise-the-document-object",
    note: "Create and initialize a Document object: the field is isomorphic-decoded before parsing, and a note records that multiple field lines are unspecified",
};
const URL_4_3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "URL",
    section: Some("4.3"),
    url: "https://url.spec.whatwg.org/#url-writing",
    note: "URL writing: valid URL string, URL code points and URL units — the alphabet the `URL=` value is judged against, which is not RFC 3986's",
};
const MDN_REFRESH: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "MDN Refresh",
    section: None,
    url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Refresh",
    note: "`Refresh` header, with browser support notes",
};

impl Rule for RefreshHeaderSyntax {
    fn id(&self) -> &'static str {
        "refresh_header_syntax"
    }

    fn scope(&self) -> crate::rules::RuleScope {
        // cite(HTML Speculative Loading § 7.8): "The `Refresh` HTTP response header is the HTTP-equivalent to a meta element with an http-equiv attribute in the Refresh state."
        crate::rules::RuleScope::Server
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

            let lines = resp.headers.get_all("refresh");
            let count = lines.iter().count();
            if count == 0 {
                return None;
            }

            // cite(HTML Document Lifecycle § 7.5.1): "We do not currently have a spec for how to handle multiple `Refresh` headers."
            // cite(Fetch § 2.2.2): "Return the values of all headers in list whose name is a byte-case-insensitive match for name, separated from each other by 0x2C 0x20"
            // The processing model is handed one string, and that string is the
            // combination of every field line — so HTML's note is not about a choice
            // between the lines, it is about a value none of them carries. Nothing is
            // measured after this: judging the first line would judge something no
            // recipient reads.
            if count > 1 {
                return Some(self.violation(
                    ctx.severity,
                    format!(
                        "Response carries {count} Refresh header field lines; HTML specifies no \
                         handling for more than one, so what a recipient does with them is not \
                         interoperable"
                    ),
                ));
            }

            let raw = lines.iter().next()?.as_bytes();
            // cite(HTML Document Lifecycle § 7.5.1): "Let value be the isomorphic decoding of the value of the header."
            // cite(Infra § 4.5): "To isomorphic decode a byte sequence input, return a string whose code point length is equal to input’s length and whose code points have the same values as the values of input’s bytes, in the same order."
            // Not `to_str()`. Every octet becomes the code point of the same value,
            // so an `obs-text` byte reaches the check that owns it — `%xE9` is a URL
            // code point and `%x85` is not, and a UTF-8 decode cannot tell them
            // apart because it refuses both.
            let decoded: String = raw.iter().map(|&b| b as char).collect();

            // cite(RFC 9110 §5.5): "A field value does not include leading or trailing whitespace."
            // HTTP's whitespace, not Infra's: the octets a sender may pad with are
            // SP and HTAB, and `str::trim` would also eat `%xA0`, which is `obs-text`
            // and belongs to the value.
            let value = decoded.trim_matches(|c| c == ' ' || c == '\t');

            // cite(HTML Speculative Loading § 7.8): "It takes the same value and works largely the same."
            // The conformance requirement `refresh_value_error` implements is written
            // for the `meta` pragma's content attribute; this is the sentence that
            // makes it this field's requirement too.
            refresh_value_error(value).map(|why| {
                self.violation(
                    ctx.severity,
                    format!("Refresh header value '{value}': {why}"),
                )
            })
        };
        Vec::from_iter(finding())
    }

    fn title(&self) -> Option<&'static str> {
        Some("Refresh header syntax")
    }

    fn description(&self) -> &'static str {
        "Validate the syntax of the `Refresh` response header. Long treated as non-standard, it is now specified by the HTML Standard (§ 7.8), which says it is the HTTP equivalent of a `meta` element with `http-equiv=\"refresh\"` and *takes the same value*. That value has exactly two conforming forms: a delay in seconds on its own, or a delay followed by `;`, one or more spaces, `URL=` (in any case), and a valid URL string that does not begin with a quote. This rule reports a value matching neither.\n\nWhere the verdicts come from, since § 7.8 states no requirement of its own: the `must` is the authoring conformance requirement written for the `meta` pragma's content attribute, and \"takes the same value\" is the sentence that carries it to the field. The URL is judged against the WHATWG URL Standard's alphabet — its *URL units* — rather than RFC 3986's, so a non-ASCII octet is a URL code point here, and a relative reference such as `1http://x` is a conforming URL rather than a malformed scheme.\n\nOnly the URL's alphabet is checked. Whether its components are in a legal order, and whether its host parses, are the URL parser's questions and are not asked.\n\nMore than one `Refresh` field line is reported on its own terms: HTML records that it has no specification for that case, so the finding is an interoperability report rather than a violation of a stated requirement, and nothing further is measured — the string a recipient parses is the combination of the lines, not any one of them."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            HTML_SPECULATIVE_LOADING_7_8,
            HTML_SEMANTICS_4_2_5_3,
            HTML_DOCUMENT_LIFECYCLE_7_5_1,
            URL_4_3,
            MDN_REFRESH,
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nRefresh: 5\n\nHTTP/1.1 200 OK\nRefresh: 10; url=/new\n\nHTTP/1.1 200 OK\nRefresh: 0; URL=/report?from=a,b;to=c",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nRefresh: bad\n\nHTTP/1.1 200 OK\nRefresh: +5\n\nHTTP/1.1 200 OK\nRefresh: 10;url=/new\n\nHTTP/1.1 200 OK\nRefresh: 5; url=\n\nHTTP/1.1 200 OK\nRefresh: 5; url=\"/new\"\n\nHTTP/1.1 200 OK\nRefresh: 5; foo=bar\n\nHTTP/1.1 200 OK\nRefresh: 5, 10",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &RefreshHeaderSyntax;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// One constructor for every fixture, taking the field's octets as written.
    /// The rule reads the raw bytes, so a fixture that can only carry a `&str`
    /// cannot express the values the isomorphic decode exists for.
    fn make_tx_with_refresh(values: &[&[u8]]) -> crate::http_transaction::HttpTransaction {
        use hyper::header::{HeaderName, HeaderValue};

        let mut tx = crate::test_helpers::make_test_transaction();
        let mut hm = hyper::HeaderMap::new();
        for v in values {
            hm.append(
                HeaderName::from_static("refresh"),
                HeaderValue::from_bytes(v).expect("fixture value is a legal field value"),
            );
        }
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hm,
            body_length: None,
            trailers: None,
        });
        tx
    }

    fn judge(tx: &crate::http_transaction::HttpTransaction) -> Option<Violation> {
        let rule = RefreshHeaderSyntax;
        crate::test_helpers::run_rule(
            &rule,
            tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
    }

    #[rstest]
    // Form one: a valid non-negative integer on its own.
    #[case(b"5")]
    #[case(b"0")]
    #[case(b"007")]
    // Form two, in both cases of the keyword and with each ASCII whitespace.
    #[case(b"10; url=/new")]
    #[case(b"10; URL=/new")]
    #[case(b"10;\turl=/new")]
    #[case(b"10;   url=/new")]
    #[case(b"10; url=http://example/")]
    // A `,` and a `;` further along are data inside the URL; the value is split
    // once, at the first `;`, and the URL runs to the end of it.
    #[case(b"5; url=/a,b")]
    #[case(b"5; url=/a;b")]
    #[case(b"0; URL=/report?from=a,b;to=c")]
    // No scheme is required: a relative reference is a valid URL string.
    #[case(b"5; url=1http://example/")]
    // `%xE9` is a URL code point. `to_str()` refused the whole field for this.
    #[case(b"5; url=/caf\xe9")]
    fn conforming_values_are_not_reported(#[case] value: &[u8]) {
        let v = judge(&make_tx_with_refresh(&[value]));
        assert!(v.is_none(), "{:?}: {v:?}", String::from_utf8_lossy(value));
    }

    #[rstest]
    #[case(b"bad", "not a valid non-negative integer")]
    #[case(b"", "not a valid non-negative integer")]
    #[case(b"   ", "not a valid non-negative integer")]
    #[case(b"5.5; url=/x", "not a valid non-negative integer")]
    // `u64::from_str` accepts a leading `+`; `1*ASCII digit` does not.
    #[case(b"+5", "not a valid non-negative integer")]
    // Neither form admits a `,` where the `;` belongs.
    #[case(b"5, 10", "not a valid non-negative integer")]
    // The second form is missing entirely, so the `;` delimits nothing.
    #[case(b"5;", "followed by nothing")]
    #[case(b"5;   ", "followed by nothing")]
    // "followed by one or more ASCII whitespace" is part of the requirement.
    #[case(b"10;url=/new", "not followed by whitespace")]
    #[case(b"5; foo=bar", "is not a `URL=` parameter")]
    #[case(b"5; url =/new", "is not a `URL=` parameter")]
    #[case(b"5; url= /new", "is not a URL unit")]
    #[case(b"5; url=", "carries no URL")]
    // "a valid URL string that does not start with a literal U+0027 … or U+0022".
    #[case(b"5; url=\"/new\"", "starts with a quote")]
    #[case(b"5; url='/new'", "starts with a quote")]
    #[case(b"5; url=/in valid", "is not a URL unit")]
    #[case(b"5; url=/x<y>", "is not a URL unit")]
    // `%x85` is `obs-text` and is not a URL code point; `%xE9` (above) is.
    #[case(b"5; url=/x\x85", "is not a URL unit")]
    #[case(b"5; url=/x%G1", "not followed by two hex digits")]
    #[case(b"5; url=/x%2", "not followed by two hex digits")]
    fn non_conforming_values_are_reported(#[case] value: &[u8], #[case] expected: &str) {
        let v = judge(&make_tx_with_refresh(&[value])).unwrap_or_else(|| {
            panic!(
                "expected a finding for {:?}",
                String::from_utf8_lossy(value)
            )
        });
        assert!(v.message.contains(expected), "{}", v.message);
    }

    #[test]
    fn std_agrees_on_ascii_whitespace() {
        // The doc comment on `is_ascii_whitespace` says std's set is the same
        // five code points. That is a claim about another crate, so it is pinned
        // here rather than trusted.
        for b in 0u8..=0x7F {
            let c = b as char;
            assert_eq!(is_ascii_whitespace(c), c.is_ascii_whitespace(), "{c:?}");
        }
    }

    #[test]
    fn no_refresh_field_is_not_a_finding() {
        assert!(judge(&make_tx_with_refresh(&[])).is_none());
    }

    #[test]
    fn several_field_lines_are_reported_even_when_each_would_pass() {
        // Both lines are conforming on their own. What a recipient parses is
        // neither of them, and HTML does not say what it is.
        let v = judge(&make_tx_with_refresh(&[b"5", b"10; url=/x"])).expect("expected a finding");
        assert!(
            v.message.contains("2 Refresh header field lines"),
            "{}",
            v.message
        );
    }

    #[test]
    fn published_examples_are_judged_by_this_rule() {
        use crate::rules::{Compliance, Rule as _};
        let rule = RefreshHeaderSyntax;

        for ex in rule.examples() {
            for block in ex.snippet.split("\n\n") {
                let mut values: Vec<&[u8]> = Vec::new();
                for (i, line) in block.lines().enumerate() {
                    if i == 0 {
                        assert!(
                            line.starts_with("HTTP/1.1 "),
                            "the first line of an example message is its status line: {line:?}"
                        );
                        continue;
                    }
                    let (name, value) = line.split_once(':').unwrap_or_else(|| {
                        panic!("example header line is not `Name: value`: {line:?}")
                    });
                    assert_eq!(name.to_ascii_lowercase(), "refresh", "{line:?}");
                    values.push(value.trim_start_matches(' ').as_bytes());
                }
                assert!(
                    !values.is_empty(),
                    "example message carries no field: {block:?}"
                );

                let v = judge(&make_tx_with_refresh(&values));
                match ex.compliance {
                    Compliance::Compliant => assert!(v.is_none(), "{block}: {v:?}"),
                    Compliance::NonCompliant => assert!(v.is_some(), "{block}"),
                }
            }
        }
    }

    #[test]
    fn scope_is_server() {
        let rule = RefreshHeaderSyntax;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let rule = RefreshHeaderSyntax;
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert("severity".to_string(), toml::Value::String("warn".into()));
        cfg.rules
            .insert("refresh_header_syntax".into(), toml::Value::Table(table));

        rule.prepare(&cfg)?;
        Ok(())
    }
}
