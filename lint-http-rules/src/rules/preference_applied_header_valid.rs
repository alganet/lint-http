// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::helpers::headers::{
    combined_field_value_as_written, list_members_as_written, parse_token_bws_word,
    quoting_is_balanced, shown_in_finding, split_semicolons_respecting_quotes,
};
use crate::lint::Violation;
use crate::rules::Rule;
use std::collections::HashMap;

pub struct PreferenceAppliedHeaderValid;

/// The preferences a request asked for, keyed by the lowercased token.
///
/// `None` in the value position is "the client named this preference and gave it
/// no value", which is the same state as `Some("")` on the wire: RFC 7240 says
/// so, and normalising it here is what keeps the comparison below from
/// reporting `""` against a value.
///
/// cite(RFC 7240 § 2): "Empty or zero-length values on both the preference token and within parameters are equivalent to no value being specified at all."
type RequestPreferences = HashMap<String, Option<String>>;

/// What the request said, and whether it could be read at all.
struct PreferSection {
    prefs: RequestPreferences,
    /// False when the `Prefer` value cannot be split into members with any
    /// confidence. The two findings that assert something is *absent* from the
    /// request stand down in that case; the ones that judge what the response
    /// wrote do not depend on it.
    readable: bool,
}

/// Read the request's `Prefer` field into the set of preferences it named.
///
/// The field is joined before it is split. A client may write its preferences
/// across several field lines and the document says what that means, so a member
/// straddling a line boundary is a member and not two halves.
///
/// cite(RFC 7240 § 2): "If multiple Prefer header fields are used, it is equivalent to a single Prefer header field with the comma-separated concatenation of all of the tokens."
fn read_prefer(headers: &hyper::HeaderMap) -> PreferSection {
    let mut prefs = RequestPreferences::new();
    let Some(value) = combined_field_value_as_written(headers, "prefer") else {
        // No `Prefer` at all is perfectly readable: the client named no
        // preferences, and every applied one is therefore unaccounted for.
        return PreferSection {
            prefs,
            readable: true,
        };
    };

    // A member list cut out of a value whose quoting never closes is not a
    // member list: everything past the stray DQUOTE collapses into one segment.
    // A finding of the form "the request never asked for this" is a claim about
    // the whole set, so it needs the set to be trustworthy.
    if !quoting_is_balanced(&value) {
        return PreferSection {
            prefs,
            readable: false,
        };
    }

    for member in list_members_as_written(&value) {
        if member.is_empty() {
            // `prefer_header_valid` owns what the client wrote; here an
            // unusable member only has to not become a preference.
            continue;
        }
        // A preference may carry parameters and an applied one may not, so only
        // the part before the first top-level `;` names the preference.
        //
        // cite(RFC 7240 § 2): "An optional set of parameters can be specified for any preference token."
        let first = split_semicolons_respecting_quotes(member)
            .into_iter()
            .next()
            .unwrap_or("");
        let Ok(parsed) = parse_token_bws_word(first) else {
            // The member has a defect this rule does not report, and with it the
            // name it was going to contribute. Reporting an applied preference
            // as unrequested on the strength of a member we could not read would
            // be stating as missing what is merely unreadable.
            return PreferSection {
                prefs: RequestPreferences::new(),
                readable: false,
            };
        };
        let name = parsed.name.to_ascii_lowercase();
        // cite(RFC 7240 § 2): "If any preference is specified more than once, only the first instance is to be considered."
        if prefs.contains_key(&name) {
            continue;
        }
        prefs.insert(name, parsed.value.filter(|v| !v.is_empty()));
    }

    PreferSection {
        prefs,
        readable: true,
    }
}

impl Rule for PreferenceAppliedHeaderValid {
    fn id(&self) -> &'static str {
        "preference_applied_header_valid"
    }

    /// The field is a response field and every sentence below is addressed to
    /// the server that wrote it. `Server` is also the only scope this engine
    /// acts on — it skips a capture with no response — and this rule has nothing
    /// to say about a request on its own.
    ///
    /// cite(RFC 7240 § 3): "The Preference-Applied response header MAY be included within a response message as an indication as to which Prefer tokens were honored by the server and applied to the processing of a request."
    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;
        let resp = tx.response.as_ref()?;

        let violation = |message: String| {
            Some(Violation {
                rule: self.id().into(),
                severity: config.severity,
                message,
            })
        };

        // Read as octets, one `char` each, and joined across the field's lines.
        // A `word` may be a `quoted-string`, `qdtext` admits `obs-text`, and
        // `HeaderValue::to_str` refuses every octet above %x7E — so the decode
        // that used to guard this loop reported `Preference-Applied: foo="café"`
        // as invalid while calling it "non-UTF8", which is wrong about the value
        // twice over. The same call answers the field's other structural
        // question: several lines are one value, so a member written across a
        // line boundary is a member.
        let applied = combined_field_value_as_written(&resp.headers, "preference-applied")?;

        // cite(RFC 7240 § 3): "Preference-Applied = "Preference-Applied" ":" 1#applied-pref"
        let members = list_members_as_written(&applied);

        // `1#` sets a floor, and the floor counts *non-empty* elements. The
        // sender expansion is where the floor is: one element, then any number
        // of further ones. What names the values is the worked example a section
        // later — `""`, `","` and `",   ,"`, which is this field value under
        // three spellings, and the second of them drew nothing from any rule in
        // the catalogue before this one.
        //
        // cite(RFC 9110 § 5.6.1.1): "1#element => element *( OWS "," OWS element )"
        // cite(RFC 9110 § 5.6.1.2): "In contrast, the following values would be invalid, since at least one non-empty element is required by the example-list production:"
        if members.iter().all(|m| m.is_empty()) {
            return violation(
                "Preference-Applied header carries no applied preference; its value is 1#applied-pref, which requires at least one non-empty member".into(),
            );
        }

        // An empty element beside a real one is the other half of the same
        // grammar, and a different requirement: § 5.6.1.2 makes a recipient
        // accept it, § 5.6.1.1 forbids the sender writing it. This rule measures
        // the sender.
        //
        // cite(RFC 9110 § 5.6.1.1): "In any production that uses the list construct, a sender MUST NOT generate empty list elements."
        if members.iter().any(|m| m.is_empty()) {
            return violation(format!(
                "Preference-Applied header contains an empty list element: '{}'",
                shown_in_finding(&applied)
            ));
        }

        let prefer = read_prefer(&tx.request.headers);

        for member in members.iter().filter(|m| !m.is_empty()) {
            // The two fields share a production and differ by exactly this, and
            // the document says so rather than leaving it to be inferred from
            // the two ABNF blocks. A `;` inside the `word`'s quoted-string is
            // `qdtext` and not a parameter, which is why the search is
            // quote-aware.
            //
            // cite(RFC 7240 § 3): "The syntax of the Preference-Applied header differs from that of the Prefer header in that parameters are not included."
            if split_semicolons_respecting_quotes(member).len() > 1 {
                return violation(format!(
                    "Preference-Applied member '{}' carries parameters, which its grammar does not include",
                    shown_in_finding(member)
                ));
            }

            // cite(RFC 7240 § 3): "applied-pref = token [ BWS "=" BWS word ]"
            let parsed = match parse_token_bws_word(member) {
                Ok(parsed) => parsed,
                Err(e) => {
                    return violation(format!(
                        "Preference-Applied member '{}' does not match applied-pref: {}",
                        shown_in_finding(member),
                        e
                    ))
                }
            };

            // The `BWS` in the production is why the parse trims around the `=`
            // at all — a recipient is required to. The sender is required not to
            // put it there, and that half was going unsaid because the trim it
            // licenses happens first and leaves nothing behind.
            //
            // cite(RFC 9110 § 5.6.3): "A sender MUST NOT generate BWS in messages."
            // cite(RFC 9110 § 5.6.3): "A recipient MUST parse for such bad whitespace and remove it before interpreting the protocol element."
            if parsed.bws {
                return violation(format!(
                    "Preference-Applied member '{}' has whitespace around its '='; the grammar admits BWS there only for historical reasons",
                    shown_in_finding(member)
                ));
            }

            // One sentence decides both comparisons this rule makes, and it
            // decides them differently.
            //
            // cite(RFC 7240 § 2): "For both preference token names and parameter names, comparison is case insensitive while values are case sensitive regardless of whether token or quoted-string values are used."
            let name = parsed.name.to_ascii_lowercase();
            // Same sentence's other clause, applied to the value: `foo=""` and
            // `foo` say the same thing, so neither can contradict the other.
            //
            // cite(RFC 7240 § 2): "Empty or zero-length values on both the preference token and within parameters are equivalent to no value being specified at all."
            let value = parsed.value.filter(|v| !v.is_empty());

            if !prefer.readable {
                continue;
            }

            // The field's own definition is what makes this a finding: its
            // members are the request's preferences, so a member the request
            // never carried is the message contradicting itself. Nothing in
            // RFC 7240 states it as a requirement, and nothing needs to — a
            // server cannot have honored a preference that was not asked for.
            //
            // cite(RFC 7240 § 3): "The Preference-Applied response header MAY be included within a response message as an indication as to which Prefer tokens were honored by the server and applied to the processing of a request."
            // `parsed.name` needs no escaping where the values around it do: the
            // parse returns a name only after finding every octet in it to be a
            // `tchar`, which is visible US-ASCII. A `word`'s content has no such
            // guarantee — `qdtext` admits HTAB and `obs-text` — so the two
            // values below go through [`shown_in_finding`] and the name does not.
            let Some(requested) = prefer.prefs.get(&name) else {
                return violation(format!(
                    "Preference-Applied names '{}', which the request's Prefer header did not ask for",
                    parsed.name
                ));
            };

            // Both sides carry the `word`'s content rather than its written
            // form, so `return="representation"` and `return=representation` are
            // the same preference honored — the same sentence that makes the
            // comparison case-sensitive says it holds "regardless of whether
            // token or quoted-string values are used".
            if let (Some(applied_value), Some(requested_value)) = (&value, requested) {
                if applied_value != requested_value {
                    return violation(format!(
                        "Preference-Applied reports '{}' applied with value '{}', where the request asked for '{}'",
                        parsed.name,
                        shown_in_finding(applied_value),
                        shown_in_finding(requested_value)
                    ));
                }
            }
        }

        None
    }

    fn title(&self) -> Option<&'static str> {
        Some("Preference-Applied header validity")
    }

    fn description(&self) -> &'static str {
        "Check the `Preference-Applied` response header against its RFC 7240 §3 grammar — `Preference-Applied = 1#applied-pref`, `applied-pref = token [ BWS \"=\" BWS word ]` — and against the request that produced it: the field's members are the preferences the server honored, so a member the request's `Prefer` header never asked for, or one reported with a different value than was asked for, is the message contradicting itself.\n\nThe field's lines are joined before they are split, because a client may spread `Prefer` over several lines and RFC 7240 §2 says several lines are one value; the value is read as octets, because a `word` may be a `quoted-string` and `qdtext` admits `obs-text`. Comparisons follow §2: preference names are matched case-insensitively, values case-sensitively, and a value's quoting is not part of it — `foo=\"bar\"` and `foo=bar` name the same value, and `foo=\"\"` and `foo` both mean no value at all.\n\nWhat it does not decide: whether a value is one the preference's own definition allows (RFC 7240 §4 gives `return` and `handling` closed value sets; `prefer_header_valid` is the rule holding the request those come from), and whether the `Prefer` the capture holds is the one the responding server saw — an intermediary between this observation point and the origin may add preferences of its own, so the comparison is against this exchange as observed. When the request's `Prefer` value cannot be split into members — its quoting never closes, or a member does not parse — both comparisons stand down rather than report as unrequested what is merely unreadable; the grammar checks on the response are unaffected."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 7240",
                section: Some("3"),
                url: "https://www.rfc-editor.org/rfc/rfc7240.html#section-3",
                note: "`Preference-Applied` — the field's definition, its grammar, and the sentence saying it is the `Prefer` grammar without parameters",
            },
            crate::rules::SpecRef {
                spec: "RFC 7240",
                section: Some("2"),
                url: "https://www.rfc-editor.org/rfc/rfc7240.html#section-2",
                note: "`Prefer` — the multi-line equivalence, the first-instance rule, the case rules for names and values, and the equivalence of an empty value with no value",
            },
            crate::rules::SpecRef {
                spec: "RFC 7240",
                section: Some("1.1"),
                url: "https://www.rfc-editor.org/rfc/rfc7240.html#section-1.1",
                note: "Where `token`, `word`, `OWS`, `BWS` and the `#rule` extension come from. The named source is RFC 7230, which RFC 9110 obsoletes; `word` is the one name RFC 9110 did not keep, though both halves of it survive as `token` and `quoted-string`",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("5.6.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1",
                note: "The `#rule` extension: §5.6.1.1 forbids the sender an empty list element, §5.6.1.2 prints the values a `1#` production rejects for having no non-empty member",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("5.6.3"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.3",
                note: "`BWS`: a recipient must remove it before interpreting the element, and a sender must not have written it — both directions are read at the `=` in `applied-pref`",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("(RFC 7240 §3's own example exchange)"),
                snippet: "PATCH /my-document HTTP/1.1\nHost: example.org\nContent-Type: application/example-patch\nPrefer: return=representation\n\nHTTP/1.1 200 OK\nContent-Type: application/json\nPreference-Applied: return=representation\nContent-Location: /my-document",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(the value's quoting is not part of the value)"),
                snippet: "GET / HTTP/1.1\nHost: example.org\nPrefer: return=\"representation\"\n\nHTTP/1.1 200 OK\nPreference-Applied: return=representation",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(server names the preference and leaves its value unstated)"),
                snippet: "GET / HTTP/1.1\nHost: example.org\nPrefer: return=representation\n\nHTTP/1.1 200 OK\nPreference-Applied: return",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(applied preference the request never asked for)"),
                snippet: "GET / HTTP/1.1\nHost: example.org\n\nHTTP/1.1 200 OK\nPreference-Applied: respond-async",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(applied-pref has no parameters)"),
                snippet: "GET / HTTP/1.1\nHost: example.org\nPrefer: return=representation\n\nHTTP/1.1 200 OK\nPreference-Applied: return; foo=bar",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(1#applied-pref requires one non-empty member)"),
                snippet: "GET / HTTP/1.1\nHost: example.org\nPrefer: return=representation\n\nHTTP/1.1 200 OK\nPreference-Applied: ,",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(BWS around the '=' is admitted by the grammar and forbidden to senders)"),
                snippet: "GET / HTTP/1.1\nHost: example.org\nPrefer: return=representation\n\nHTTP/1.1 200 OK\nPreference-Applied: return = representation",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &PreferenceAppliedHeaderValid;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// Build a transaction from raw `Prefer` and `Preference-Applied` field
    /// lines, so a test can write more than one of either and can write octets
    /// no `&str` API would carry.
    fn tx_with(prefer: &[&[u8]], applied: &[&[u8]]) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut req = hyper::HeaderMap::new();
        for line in prefer {
            req.append(
                "prefer",
                hyper::header::HeaderValue::from_bytes(line).expect("field line"),
            );
        }
        tx.request.headers = req;
        let mut resp = hyper::HeaderMap::new();
        for line in applied {
            resp.append(
                "preference-applied",
                hyper::header::HeaderValue::from_bytes(line).expect("field line"),
            );
        }
        tx.response.as_mut().unwrap().headers = resp;
        tx
    }

    fn check(tx: &crate::http_transaction::HttpTransaction) -> Option<Violation> {
        let rule = PreferenceAppliedHeaderValid;
        crate::test_helpers::run_rule(
            &rule,
            tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
    }

    #[test]
    fn scope_is_server() {
        let rule = PreferenceAppliedHeaderValid;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }

    #[rstest]
    // The exchange RFC 7240 § 3 prints.
    #[case(&["return=representation"], &["return=representation"], false)]
    #[case(&["return=representation"], &["return"], false)]
    #[case(&["handling=lenient"], &["handling=lenient"], false)]
    // Names compare case-insensitively, values do not.
    #[case(&["Return=representation"], &["return=representation"], false)]
    #[case(&["return=representation"], &["return=REPRESENTATION"], true)]
    // A `word` is a token *or* a quoted-string, and the quoting is not the value.
    #[case(&["return=\"representation\""], &["return=representation"], false)]
    #[case(&["return=representation"], &["return=\"representation\""], false)]
    // `foo=""` and `foo` are the same statement, in either direction.
    #[case(&["foo=\"\""], &["foo"], false)]
    #[case(&["foo"], &["foo=\"\""], false)]
    #[case(&["foo=\"\""], &["foo=bar"], false)]
    // A client that named a preference and no value asked for whatever the
    // preference's own definition defaults to, so a server stating one is not
    // contradicting it; the comparison has two values or it does not happen.
    #[case(&["foo"], &["foo=bar"], false)]
    // A quoted-string may hold the delimiters of the grammar around it.
    #[case(&["foo=\"a,b\""], &["foo=\"a,b\""], false)]
    #[case(&["foo=\"a;b\""], &["foo=\"a;b\""], false)]
    #[case(&["foo=\"a=b\""], &["foo=\"a=b\""], false)]
    // Only the first instance of a preference is considered.
    #[case(&["return=minimal, return=representation"], &["return=minimal"], false)]
    #[case(&["return=minimal, return=representation"], &["return=representation"], true)]
    // The contradictions.
    #[case(&[], &["respond-async"], true)]
    #[case(&["return=minimal"], &["return=representation"], true)]
    // The grammar.
    #[case(&["return=representation"], &["return; foo=bar"], true)]
    #[case(&["return=representation"], &["return = representation"], true)]
    #[case(&["return=representation"], &["return= representation"], true)]
    #[case(&["return=representation"], &["return ="], true)]
    #[case(&["foo"], &["f@o"], true)]
    #[case(&["foo"], &["foo=bad@"], true)]
    #[case(&["foo=\"bar\""], &["foo=\"bar"], true)]
    #[case(&["foo"], &["foo="], true)]
    // `1#applied-pref` and its empty elements.
    #[case(&["foo"], &[""], true)]
    #[case(&["foo"], &[","], true)]
    #[case(&["foo"], &[",   ,"], true)]
    #[case(&["foo, bar"], &["foo,,bar"], true)]
    #[case(&["foo, bar"], &["foo,bar,"], true)]
    fn check_cases(
        #[case] prefer: &[&str],
        #[case] applied: &[&str],
        #[case] expect_violation: bool,
    ) {
        let prefer: Vec<&[u8]> = prefer.iter().map(|s| s.as_bytes()).collect();
        let applied: Vec<&[u8]> = applied.iter().map(|s| s.as_bytes()).collect();
        let v = check(&tx_with(&prefer, &applied));
        assert_eq!(
            v.is_some(),
            expect_violation,
            "Prefer {:?} / Preference-Applied {:?} gave {:?}",
            prefer,
            applied,
            v
        );
    }

    /// `qdtext` admits `obs-text`, so this member is conforming in both fields
    /// and neither can be judged through a UTF-8 decode.
    #[test]
    fn obs_text_inside_a_quoted_string_is_not_a_finding() {
        let line: &[u8] = b"foo=\"caf\xE9\"";
        assert!(check(&tx_with(&[line], &[line])).is_none());
    }

    /// The same octet outside the quoted-string is a `token` character that no
    /// `tchar` admits, and it has to be reported as the octet it is rather than
    /// as an encoding complaint about the whole field.
    #[test]
    fn obs_text_outside_a_quoted_string_is_reported_as_the_octet() {
        let v = check(&tx_with(&[b"foo"], &[b"caf\xE9"])).expect("finding");
        assert!(v.message.contains("0xE9"), "{}", v.message);
    }

    /// § 5.2 makes several lines one value, so a member written across the
    /// boundary is one member — and the comma the join inserts is the one the
    /// list grammar prints.
    #[test]
    fn a_member_split_across_field_lines_is_one_member() {
        assert!(check(&tx_with(&[b"foo=\"a,b\""], &[b"foo=\"a", b"b\""])).is_none());
    }

    /// The join is also what makes an empty field line an empty list element.
    #[test]
    fn an_empty_field_line_beside_a_member_is_an_empty_list_element() {
        let v = check(&tx_with(&[b"foo"], &[b"", b"foo"])).expect("finding");
        assert!(v.message.contains("empty list element"), "{}", v.message);
    }

    /// A `Prefer` value whose quoting never closes cannot be cut into members,
    /// and the finding this rule would make from it is a claim about the whole
    /// set. It stands down; the response's own grammar is still judged.
    #[test]
    fn an_unreadable_prefer_stands_the_comparisons_down() {
        assert!(check(&tx_with(&[b"foo=\"unterminated"], &[b"bar"])).is_none());
        let v = check(&tx_with(&[b"foo=\"unterminated"], &[b"b@r"])).expect("finding");
        assert!(
            v.message.contains("does not match applied-pref"),
            "{}",
            v.message
        );
    }

    /// The finding is the sender's `BWS`, so it has to name that and not the
    /// value, which the recipient half of the same sentence says is `return`
    /// either way.
    #[test]
    fn bws_is_reported_without_disturbing_the_value() {
        let v = check(&tx_with(
            &[b"return=representation"],
            &[b"return = representation"],
        ))
        .expect("finding");
        assert!(v.message.contains("BWS"), "{}", v.message);
    }

    /// `qdtext` admits HTAB, so a conforming value can carry an octet that would
    /// break the line of a finding rather than appear in it. The message is
    /// derived data and gets its own test.
    #[test]
    fn a_value_reaching_a_finding_is_escaped_into_it() {
        let v = check(&tx_with(&[b"foo=bar"], &[b"foo=\"a\tb\""])).expect("finding");
        assert!(
            v.message.contains("a\\tb") && !v.message.contains('\t'),
            "{}",
            v.message
        );
    }

    /// The neighbour named in `description()` is the one that judges what the
    /// client wrote; run it rather than describe it.
    #[test]
    fn prefer_syntax_belongs_to_the_neighbouring_rule() {
        let neighbour = crate::rules::REGISTERED_RULES
            .iter()
            .find(|r| r.id() == "prefer_header_valid")
            .expect("prefer_header_valid is registered");
        let tx = tx_with(&[b"f@o"], &[b"bar"]);
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "prefer_header_valid",
            "preference_applied_header_valid",
        ]);
        let hist = crate::transaction_history::TransactionHistory::empty();
        assert!(
            crate::test_helpers::run_rule(*neighbour, &tx, &hist, &cfg).is_some(),
            "the Prefer rule reports the member this one declines to read"
        );
    }
}
