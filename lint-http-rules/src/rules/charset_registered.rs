// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::charset::{CHARSET_EMPTY, CHARSET_UNREGISTERED, RFC_9110_8_3_2};
use crate::violations::parameter::{PARAMETER_VALUE_EMPTY, RFC_9110_5_6_6};
use crate::violations::quoted_pair::QUOTED_PAIR_MALFORMED;
use crate::violations::quoted_string::{
    quoted_string_defect, QUOTED_STRING_CONTROL_CHARACTER_FORBIDDEN,
    QUOTED_STRING_DELIMITER_MISSING, QUOTED_STRING_QUOTE_ESCAPE_MISSING, RFC_9110_5_6_4,
};
use crate::violations::token::{
    token_character, RFC_9110_5_6_2, TOKEN_CHARACTER_FORBIDDEN,
    TOKEN_WHITESPACE_OR_CONTROL_FORBIDDEN,
};
use crate::violations::ViolationDef;

pub struct CharsetRegistered;

/// What this rule reports about the *parameter* it reads, which is everything
/// it can say before the name is a charset at all. `charset=` with nothing
/// after it, a `quoted-string` that does not close, an unquoted value holding
/// an octet no `tchar` admits: none of those is about character sets, and each
/// is the same defect `content_type_valid` reports about the same field line.
///
/// What stays on the older API is what this rule is named for — a name that is
/// not in the configured list, and a `charset=""` whose quoting is well formed
/// and whose *name* is empty. The second is the pair worth keeping apart:
/// `charset=` is a parameter with no value and `charset=""` is a parameter
/// whose value is a `quoted-string` deriving exactly as it should, holding a
/// charset name of nothing. One is § 5.6.6's defect and the other is § 8.3.2's,
/// and the `charset` subject that owns the second is unwritten.
static DECLARED: &[&ViolationDef] = &[
    &CHARSET_EMPTY,
    &CHARSET_UNREGISTERED,
    &PARAMETER_VALUE_EMPTY,
    &TOKEN_WHITESPACE_OR_CONTROL_FORBIDDEN,
    &TOKEN_CHARACTER_FORBIDDEN,
    &QUOTED_STRING_DELIMITER_MISSING,
    &QUOTED_PAIR_MALFORMED,
    &QUOTED_STRING_QUOTE_ESCAPE_MISSING,
    &QUOTED_STRING_CONTROL_CHARACTER_FORBIDDEN,
];

/// The specification references this rule declares beyond the catalogue's
/// § 8.3.2, each named so a finding site can cite the one it enforces.
/// `specifications()` below is built from exactly these, so the docs and the
/// citations cannot name different text.
const RFC_2978_2_3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 2978",
    section: Some("2.3"),
    url: "https://www.rfc-editor.org/rfc/rfc2978.html#section-2.3",
    note: "`mime-charset`, the production a charset name actually follows. It and `token` are incomparable — `{`/`}` on one side, `*`/`.`/`|` on the other — so checking `token` is stricter in one direction and looser in the other, and neither direction changes a verdict",
};
const IANA_CHARACTER_SETS: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "IANA Character Sets",
    section: None,
    url: "https://www.iana.org/assignments/character-sets/character-sets.xhtml",
    note: "The registry this rule is named after but does not read; the configured `allowed` array stands in for it",
};

impl RuleMeta for CharsetRegistered {
    fn id(&self) -> &'static str {
        "charset_registered"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
severity = "warn"
allowed = ["utf-8", "iso-8859-1", "us-ascii"]
"#
    }

    fn prepare(&self, cfg: &crate::config::Config) -> anyhow::Result<crate::rules::ResolvedRule> {
        let severity = crate::rules::get_rule_severity_required(cfg, self.id())?;
        // Entries are folded once at prepare time rather than at every
        // comparison, which is sound because the matching itself is defined to
        // ignore case.
        // cite(RFC 9110 § 8.3.2): "In both cases, charset names are matched case-insensitively."
        let allowed = crate::helpers::rule_config::parse_lowercased_list(
            cfg,
            self.id(),
            "allowed",
            "acceptable charset names",
            "['utf-8','iso-8859-1']",
        )?;
        // The two standard keys, **after** this rule's own options, so a config
        // naming a bad option still fails on that option.
        crate::rules::validate_rule_table(cfg, self.id())?;
        Ok(crate::rules::ResolvedRule {
            severity,
            state: Box::new(crate::helpers::rule_config::AllowedList { allowed }),
        })
    }

    fn description(&self) -> &'static str {
        "If a `Content-Type` header carries a `charset` parameter, this rule checks the name against an allowlist you configure. It also reports an empty `charset`, a malformed quoted-string, and characters that do not belong in the name.\n\n**It does not consult the IANA registry**, despite the rule's name: there is no lookup, and a charset is \"registered\" as far as this rule is concerned exactly when your `allowed` array covers it. RFC 9110 §8.3.2 says charset names *ought to* be registered, which is the motivation for the rule, but the check itself is your policy. Matching is case-insensitive, as §8.3.2 requires, and a quoted value is compared after unescaping, since the quoted and unquoted forms are equivalent.\n\n**`token` is not the charset production.** An unquoted name is checked against `token`, while a charset name follows `mime-charset` (RFC 2978 §2.3). The two sets are *incomparable*: `mime-charset` admits `{` and `}` that `token` rejects, and `token` admits `*`, `.` and `|` that `mime-charset` rejects — so `charset=utf.8` reaches the allowlist rather than being called malformed. Neither direction changes a verdict: RFC 9110 §8.3.2 says no registered charset name uses braces, and a name carrying `.` or `*` is reported by the allowlist check if it is not configured. Only the wording of the finding differs.\n\n**Scope:** this rule reports only on charsets. A `Content-Type` that does not parse as a `media-type`, and the presence of more than one `Content-Type` field line, are both `content_type_valid`'s findings. It reads every `Content-Type` line in the header section of each message; trailers are not read, since a `Content-Type` there is malformed framing rather than a charset question.\n\n**One silence worth knowing about:** an unbalanced quote in an *earlier* parameter swallows the rest of the value, so `boundary=\"unterminated; charset=bogus` yields no charset finding here. The value is malformed and `content_type_valid` reports it; there is genuinely no parameter list left to read once the quoting breaks."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            RFC_9110_8_3_2,
            RFC_9110_5_6_6,
            RFC_9110_5_6_2,
            RFC_9110_5_6_4,
            RFC_2978_2_3,
            IANA_CHARACTER_SETS,
        ]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "GET / HTTP/1.1\nHost: example.com\nContent-Type: text/plain; charset=utf-8",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nContent-Type: text/html; charset=\"UTF-8\"\nX-Content-Type-Options: nosniff\n\n<html>...</html>",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nContent-Type: text/plain; charset=unknown-charset",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nContent-Type: text/plain; charset=\"unfinished",
            },
        ]
    }
}

impl Rule for CharsetRegistered {
    // The parameter this rule reads lives in Content-Type, and it is that field's
    // definition — not the charset section — that puts both directions in scope:
    // a request and a response each carry a representation.
    // cite(RFC 9110 § 8.3): "The "Content-Type" header field indicates the media type of the associated representation: either the representation enclosed in the message content or the selected representation, as determined by the message semantics."
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
            let config: &crate::helpers::rule_config::AllowedList = ctx.state();
            use crate::helpers::media_type::parse_media_type;

            let check_header = |which: &str, val: &str| -> Option<Violation> {
                // A value that is not a media-type at all has no parameters to read,
                // and saying so is `content_type_valid`'s finding, not
                // this one's. The `media-type` grammar is the helper's.
                let parsed = match parse_media_type(val) {
                    Ok(p) => p,
                    Err(_) => return None,
                };

                if let Some(params) = parsed.params {
                    // Quote-aware, because a `;` inside a quoted parameter value does
                    // not separate parameters. A raw `split(';')` cut such a value in
                    // half and then read the halves as parameters of their own, so a
                    // boundary like `boundary="x; charset=bogus"` produced a charset
                    // finding for a message that has no charset parameter at all.
                    // Every other rule that walks media-type parameters already uses
                    // this helper; this one was the exception.
                    //
                    // The walk is `helpers::headers::parameters`, which owns the
                    // split, the bracketed-empty skip and the cut at the first `=`.
                    // A segment with no `=` is not this rule's finding —
                    // `content_type_valid` reads the same field
                    // through `media_type_parts_defect` and reports it there — so it
                    // is skipped rather than judged, and the whitespace beside the
                    // `=` is the leniency this rule publishes.
                    for parameter in crate::helpers::parameter::parameters(params) {
                        let Ok(parameter) = parameter else { continue };
                        let value = parameter.value;
                        // cite(RFC 9110 § 5.6.6): "Parameter names are case-insensitive."
                        if parameter.name.eq_ignore_ascii_case("charset") {
                            // Nothing after the "=" is not a charset name that
                            // happens to be unregistered — it is not a
                            // `parameter-value` at all, which is the parameter's
                            // defect and not this field's. The sentence saying so
                            // is on the def, where the three other rules reporting
                            // it read the same one.
                            if value.is_empty() {
                                return Some(ctx.report_with(
                                    &PARAMETER_VALUE_EMPTY,
                                    format!(
                                        "Invalid Content-Type in {}: empty 'charset' parameter",
                                        which
                                    ),
                                ));
                            }

                            // The two alternatives of `parameter-value`, each
                            // handed to the helper that owns its grammar:
                            // `quoted-string` is unescaped and validated in one
                            // step, `token` is checked character by character.
                            // A charset name is compared after unescaping, since
                            // "the quoted and unquoted values are equivalent".
                            let mut value_owned: Option<String> = None;
                            if value.starts_with('"') {
                                match crate::helpers::quoted_string::unescape_quoted_string(value) {
                                    Ok(u) => value_owned = Some(u),
                                    Err(defect) => {
                                        return Some(ctx.report_with(
                                            quoted_string_defect(defect),
                                            format!(
                                                "Invalid Content-Type in {}: 'charset' quoted-string invalid: {}",
                                                which, defect.message(value)
                                            ),
                                        ))
                                    }
                                }
                            } else {
                                // `token` is not the charset production, and the
                                // two sets are *incomparable* rather than one
                                // being a subset. `mime-charset` (RFC 2978 §2.3)
                                // admits "{" and "}", which `token` does not;
                                // `token` admits "*", "." and "|", which
                                // `mime-charset` does not. So this check is
                                // stricter in one direction and looser in the
                                // other — `charset=utf.8` reaches the allowlist
                                // instead of being called malformed.
                                //
                                // Neither direction changes a verdict. A name
                                // with braces is not registered (RFC 9110 §8.3.2
                                // says so outright), and a name with "." or "*"
                                // that is not in the allowlist is reported by the
                                // membership check below. Only the wording of the
                                // finding differs. (§8.3.2 makes this point in a
                                // gutter-marked note apycite cannot quote.)
                                if let Some(c) =
                                    crate::helpers::token::find_invalid_token_char(value)
                                {
                                    return Some(ctx.report_with(
                                        token_character(c),
                                        format!(
                                            "Invalid Content-Type in {}: charset contains invalid character '{}'",
                                            which, c
                                        ),
                                    ));
                                }
                            }
                            let value = value_owned.as_deref().unwrap_or(value);

                            // `charset=""` reaches here and the branch above it
                            // does not: the value *is* a `parameter-value`, a
                            // `quoted-string` deriving exactly as it should, and
                            // what is empty is the charset name inside it. So this
                            // is § 8.3.2's defect rather than § 5.6.6's, and it
                            // waits for a `charset` subject — the two look like
                            // one finding and are two.
                            if value.is_empty() {
                                return Some(ctx.report_with(
                                    &CHARSET_EMPTY,
                                    format!(
                                        "Invalid Content-Type in {}: empty 'charset' parameter",
                                        which
                                    ),
                                ));
                            }

                            // The rule's name says IANA; the code says the
                            // operator's `allowed` array. The registry is never
                            // consulted — there is no lookup — and the "ought
                            // to" that motivates the whole rule is quoted on
                            // `charset_unregistered`, which is what this
                            // reports. The fold is the matching rule, not a
                            // convenience, and that sentence stays here because
                            // it is what this comparison does rather than what
                            // the defect is.
                            // cite(RFC 9110 § 8.3.2): "In both cases, charset names are matched case-insensitively."
                            if !config.allowed.contains(&value.to_ascii_lowercase()) {
                                return Some(ctx.report_with(
                                    &CHARSET_UNREGISTERED,
                                    format!("Unrecognized charset '{}' in {} header", value, which),
                                ));
                            }
                        }
                    }
                }
                None
            };

            // Every Content-Type field line, not just the first. `get_header_str`
            // returns one value, and §8.3 is explicit that implementations differ
            // over which member of a duplicated Content-Type they act on — so no
            // line can be dismissed as the one nobody reads. The loop reports the
            // first unregistered charset it finds, which is a choice among equals
            // rather than a claim about precedence.
            //
            // That there is more than one line is `content_type_valid`'s
            // finding to report; this rule adds nothing by repeating it, and says
            // only what it owns: whether a charset it can see is recognized.
            let check_all = |which: &str, headers: &hyper::HeaderMap| -> Option<Violation> {
                for hv in headers.get_all("content-type").iter() {
                    // Decoded from the raw octets, not through `to_str`, which
                    // refuses `obs-text` — legal in a `quoted-string`, so
                    // `charset="<0xE4>bogus"` and any value with obs-text in a
                    // *neighbouring* parameter are well-formed media-types whose
                    // charset still has to be judged. Skipping them meant an
                    // unregistered charset alongside an obs-text parameter was
                    // reported by nothing at all. Where obs-text is not legal, in an
                    // unquoted `token`, the check below already rejects it.
                    // cite(RFC 9110 § 5.5): "A recipient SHOULD treat other allowed octets in field content (i.e., obs-text) as opaque data."
                    let s = crate::helpers::headers::field_line_as_written(hv);
                    if let Some(v) = check_header(which, &s) {
                        return Some(v);
                    }
                }
                None
            };

            if let Some(v) = check_all("request", &tx.request.headers) {
                return Some(v);
            }
            if let Some(resp) = &tx.response {
                if let Some(v) = check_all("response", &resp.headers) {
                    return Some(v);
                }
            }

            None
        };
        Vec::from_iter(finding())
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &CharsetRegistered;

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;
    use rstest::rstest;

    fn make_cfg() -> crate::config::Config {
        let mut cfg = crate::config::Config::default();
        cfg.rules.insert(
            "charset_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(vec![
                        toml::Value::String("utf-8".into()),
                        toml::Value::String("iso-8859-1".into()),
                        toml::Value::String("us-ascii".into()),
                    ]),
                );
                t
            }),
        );
        cfg
    }

    /// One `Content-Type` line, two rules, one id — and a third field with a
    /// different parameter name reaching the same one.
    ///
    /// `charset=` is read by this rule for its name and by
    /// `content_type_valid` for its grammar, and before the def existed the two
    /// wrote different sentences about the same absent value with no name in
    /// common. `boundary=` is the same defect under another parameter, which is
    /// the claim a subject named after the *production* makes and a subject
    /// named after a field cannot.
    #[test]
    fn an_empty_parameter_value_is_one_id_across_three_readings() {
        let response_with = |ct: &str| {
            let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
            tx.response.as_mut().expect("a response").headers =
                crate::test_helpers::make_headers_from_pairs(&[("content-type", ct)]);
            tx
        };
        let history = crate::transaction_history::TransactionHistory::empty();

        let charset = crate::test_helpers::run_rule(
            &CharsetRegistered,
            &response_with("text/plain; charset="),
            &history,
            &make_cfg(),
        )
        .expect("a finding about the charset parameter");
        assert_eq!(charset.violation, "parameter_value_empty");

        let grammar = crate::test_helpers::run_rule(
            &crate::rules::content_type_valid::ContentTypeValid,
            &response_with("text/plain; charset="),
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&["content_type_valid"]),
        )
        .expect("a finding about the field");
        assert_eq!(grammar.violation, charset.violation);
        assert_ne!(
            grammar.message, charset.message,
            "each rule keeps its wording"
        );

        let boundary = crate::test_helpers::run_rule(
            &crate::rules::multipart_boundary_syntax::MultipartBoundarySyntax,
            &response_with("multipart/mixed; boundary="),
            &history,
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "multipart_boundary_syntax",
            ]),
        )
        .expect("a finding about the boundary parameter");
        assert_eq!(boundary.violation, charset.violation);
    }

    /// `charset=""` is the pair that must not collapse into the one above: the
    /// value is a `quoted-string` and derives exactly as § 5.6.6 says, so what
    /// is empty is the charset name — a defect of the name and not of the
    /// parameter carrying it, which is why the two answer under different ids.
    #[test]
    fn a_quoted_empty_charset_is_not_the_parameters_defect() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().expect("a response").headers =
            crate::test_helpers::make_headers_from_pairs(&[(
                "content-type",
                "text/plain; charset=\"\"",
            )]);
        let found = crate::test_helpers::run_rule(
            &CharsetRegistered,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &make_cfg(),
        )
        .expect("a finding");
        assert_eq!(found.violation, "charset_empty");
        assert_ne!(found.violation, "parameter_value_empty");
    }

    #[rstest]
    #[case(Some("text/plain; charset=utf-8"), false)]
    #[case(Some("text/html; charset=ISO-8859-1"), false)]
    #[case(Some("text/plain; charset=us-ascii"), false)]
    #[case(Some("text/plain"), false)]
    #[case(Some("text/plain; charset=unknown-charset"), true)]
    #[case(Some("text/plain; charset=us!ascii"), true)]
    #[case(Some("text/plain; charset=\"UTF-8\""), false)]
    #[case(Some("text/plain; charset=\"\""), true)]
    // A ";" inside a quoted parameter value does not start a new parameter.
    // These have no charset parameter at all, so there is nothing to report.
    #[case(Some("multipart/form-data; boundary=\"x; charset=bogus\""), false)]
    #[case(Some("multipart/form-data; boundary=\"x; charset=utf-8\""), false)]
    // A real charset whose quoted value contains ";" is read whole, so the
    // verdict is "unrecognized", not "malformed quoted-string".
    #[case(Some("text/plain; charset=\"a;b\""), true)]
    // Still found when it follows a quoted value carrying a ";".
    #[case(Some("multipart/form-data; boundary=\"a;b\"; charset=utf-8"), false)]
    #[case(Some("multipart/form-data; boundary=\"a;b\"; charset=bogus"), true)]
    #[case(None, false)]
    fn check_response_cases(
        #[case] ct: Option<&str>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = CharsetRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        if let Some(v) = ct {
            tx.response.as_mut().unwrap().headers =
                crate::test_helpers::make_headers_from_pairs(&[("content-type", v)]);
        }

        let violation = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(violation.is_some());
        } else {
            assert!(violation.is_none());
        }
        Ok(())
    }

    /// Every published snippet is run through this rule and, for the Compliant
    /// ones, through the other rules that inspect `Content-Type` on the side of
    /// the message the example shows. Nothing else does this, so a snippet this
    /// rule accepts but a sibling rejects would ship in the docs as the
    /// recommended spelling. Four families have now published one.
    ///
    /// Deliberately not in the list: `content_type_present`, which fires
    /// on a request-side example only because the synthetic response carries no
    /// Content-Type — a fixture artefact, not a disagreement about the snippet.
    #[test]
    fn published_examples_survive_the_other_content_type_rules() {
        use crate::rules::{Compliance, RuleMeta as _};
        let rule = CharsetRegistered;
        // The example config is the one the docs describe, so the allowlist the
        // examples are judged against is the one a reader would have.
        let toml_src = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../config_example.toml"),
        )
        .expect("config_example.toml must be readable");
        let cfg: crate::config::Config =
            toml::from_str(&toml_src).expect("config_example.toml must parse");
        let siblings: [(&str, &dyn Rule); 4] = [
            (
                "well-formed",
                &crate::rules::content_type_valid::ContentTypeValid,
            ),
            (
                "charset presence",
                &crate::rules::charset_present::CharsetPresent,
            ),
            (
                "media-type allowlist",
                &crate::rules::content_type_registered::ContentTypeRegistered,
            ),
            (
                "nosniff",
                &crate::rules::x_content_type_options_present::XContentTypeOptionsPresent,
            ),
        ];

        for ex in rule.examples() {
            // Every header line is fed in, not just Content-Type: dropping one
            // silently would mean judging a message the example does not show.
            let mut pairs: Vec<(&str, &str)> = Vec::new();
            let mut in_headers = true;
            for line in ex.snippet.lines() {
                if line.starts_with("HTTP/") || line.contains(" HTTP/1.1") {
                    continue;
                }
                if line.is_empty() {
                    in_headers = false;
                    continue;
                }
                if !in_headers {
                    continue; // message body
                }
                let (k, v) = line.split_once(": ").unwrap_or_else(|| {
                    panic!("example header line is not `Name: value`: {line:?}")
                });
                pairs.push((k, v));
            }
            assert!(
                pairs
                    .iter()
                    .any(|(k, _)| k.eq_ignore_ascii_case("content-type")),
                "example carries no Content-Type: {}",
                ex.snippet
            );

            // Examples are written as whole messages, so honour the start-line.
            let on_response = ex.snippet.starts_with("HTTP/");
            let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
            if on_response {
                tx.response.as_mut().unwrap().headers =
                    crate::test_helpers::make_headers_from_pairs(&pairs);
            } else {
                tx.request.headers = crate::test_helpers::make_headers_from_pairs(&pairs);
            }
            let history = crate::transaction_history::TransactionHistory::empty();

            let v = crate::test_helpers::run_rule(&rule, &tx, &history, &cfg);
            match ex.compliance {
                Compliance::Compliant => {
                    assert!(
                        v.is_none(),
                        "rule rejects its Compliant example {:?}: {v:?}",
                        ex.snippet
                    );
                    for (name, sibling) in siblings {
                        let other = crate::test_helpers::run_rule(sibling, &tx, &history, &cfg);
                        assert!(
                            other.is_none(),
                            "the {name} rule rejects a Compliant example {:?}: {other:?}",
                            ex.snippet
                        );
                    }
                }
                Compliance::NonCompliant => {
                    let v = v.unwrap_or_else(|| {
                        panic!("rule accepts its NonCompliant example {:?}", ex.snippet)
                    });
                    // The example must fail for *this* rule's reason.
                    assert_eq!(v.rule, rule.id(), "{:?} -> {v:?}", ex.snippet);
                }
            }
        }
    }

    #[rstest]
    // An unbalanced quote in an earlier parameter swallows the rest of the
    // value, so no charset parameter survives to be judged. The value is
    // malformed and `content_type_valid` reports it; there is
    // genuinely nothing left to read here. Pinned so the silence is a decision.
    #[case("text/plain; boundary=\"unterminated; charset=bogus")]
    #[case("text/plain; boundary=x\"; charset=bogus")]
    #[case("text/plain; x=\"a\"b\"; charset=bogus")]
    #[case("text/plain; boundary=\"q\\\"; charset=bogus")]
    fn an_unbalanced_quote_earlier_in_the_value_leaves_no_charset(#[case] val: &str) {
        let rule = CharsetRegistered;
        let cfg = make_cfg();
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-type", val)]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none(), "{val} -> {v:?}");

        // ...and the sibling that owns malformed values does report it.
        let sibling_cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["content_type_valid"]);
        let other = crate::test_helpers::run_rule(
            &crate::rules::content_type_valid::ContentTypeValid,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &sibling_cfg,
        );
        assert!(other.is_some(), "{val} is unreported by both rules");
    }

    #[rstest]
    // obs-text is legal in a quoted-string, so these are well-formed media
    // types whose charset still has to be judged. `to_str` refused them and the
    // rule went silent, which meant nothing in the linter reported the charset.
    #[case(b"text/plain; charset=bogus; x=\"\xe4\"", true)]
    #[case(b"text/plain; charset=\"\xe4bogus\"", true)]
    #[case(b"text/plain; charset=\"\xe4\"; x=1", true)]
    // obs-text does not make a registered charset unregistered.
    #[case(b"text/plain; charset=utf-8; x=\"\xe4\"", false)]
    fn obs_text_does_not_hide_the_charset(#[case] raw: &[u8], #[case] expect_violation: bool) {
        use hyper::header::HeaderValue;
        let rule = CharsetRegistered;
        let cfg = make_cfg();
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        hm.insert("content-type", HeaderValue::from_bytes(raw).unwrap());
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = hm;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert_eq!(
            v.is_some(),
            expect_violation,
            "{:?} -> {v:?}",
            String::from_utf8_lossy(raw)
        );
    }

    #[rstest]
    #[case(&["text/plain; charset=utf-8", "text/plain; charset=bogus"], true)]
    #[case(&["text/plain; charset=bogus", "text/plain; charset=utf-8"], true)]
    #[case(&["text/plain; charset=utf-8", "text/plain; charset=us-ascii"], false)]
    fn every_field_line_is_checked(#[case] values: &[&str], #[case] expect_violation: bool) {
        // An unregistered charset on a second Content-Type line used to be
        // invisible, though RFC 9110 §8.3 says a recipient may well be the one
        // acting on it. That two lines are present is a different rule's
        // finding, so this rule stays quiet about the count.
        let rule = CharsetRegistered;
        let cfg = make_cfg();
        let pairs: Vec<(&str, &str)> = values.iter().map(|v| ("content-type", *v)).collect();
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&pairs);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert_eq!(v.is_some(), expect_violation, "{values:?} -> {v:?}");
        if let Some(v) = v {
            assert!(!v.message.contains("Multiple"), "{}", v.message);
        }
    }

    #[rstest]
    #[case(Some("text/plain; charset=utf-8"), false)]
    #[case(Some("text/plain; charset=unknown-charset"), true)]
    #[case(Some("text/plain; charset=us!ascii"), true)]
    #[case(Some("text/plain; charset=\"broken"), true)]
    #[case(None, false)]
    fn check_request_cases(
        #[case] ct: Option<&str>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = CharsetRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction();
        if let Some(v) = ct {
            tx.request.headers =
                crate::test_helpers::make_headers_from_pairs(&[("content-type", v)]);
        }

        let violation = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(violation.is_some());
        } else {
            assert!(violation.is_none());
        }
        Ok(())
    }

    #[test]
    fn parse_config_requires_allowed_array() {
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&["charset_registered"]);
        let res = CharsetRegistered.prepare(&cfg);
        assert!(res.is_err());
    }

    #[test]
    fn parse_config_rejects_empty_allowed_array() {
        let mut cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["charset_registered"]);
        cfg.rules.insert(
            "charset_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert("allowed".into(), toml::Value::Array(vec![]));
                t
            }),
        );

        let res = CharsetRegistered.prepare(&cfg);
        assert!(res.is_err());
    }

    #[test]
    fn parse_config_rejects_non_string_allowed_item() {
        let mut cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["charset_registered"]);
        cfg.rules.insert(
            "charset_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(vec![toml::Value::Integer(1)]),
                );
                t
            }),
        );

        let res = CharsetRegistered.prepare(&cfg);
        assert!(res.is_err());
    }

    #[test]
    fn parse_config_rejects_allowed_not_array() {
        let mut cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["charset_registered"]);
        cfg.rules.insert(
            "charset_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert("allowed".into(), toml::Value::String("utf-8".into()));
                t
            }),
        );
        let res = CharsetRegistered.prepare(&cfg);
        assert!(res.is_err());
    }

    #[test]
    fn parse_config_rejects_non_table_rule_cfg() {
        let mut cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["charset_registered"]);
        cfg.rules.insert(
            "charset_registered".into(),
            toml::Value::String("not-a-table".into()),
        );
        let res = CharsetRegistered.prepare(&cfg);
        assert!(res.is_err());
    }

    #[test]
    fn malformed_content_type_is_ignored() {
        // If Content-Type fails to parse, this rule should return None (other rules handle well-formedness)
        let rule = CharsetRegistered;
        let cfg = make_cfg();
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-type", "text")]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn charset_name_case_and_spacing_ok() {
        let rule = CharsetRegistered;
        let cfg = make_cfg();
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-type",
            "text/plain; CHARSET = UTF-8",
        )]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn param_without_equals_is_ignored_response() {
        // A parameter without an '=' should be ignored, producing no violation
        let rule = CharsetRegistered;
        let cfg = make_cfg();
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-type",
            "text/plain; charset",
        )]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn param_without_equals_is_ignored_request() {
        // Same as response, but for requests
        let rule = CharsetRegistered;
        let cfg = make_cfg();
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-type",
            "text/plain; charset",
        )]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn trailing_semicolon_is_ignored() {
        // Trailing semicolons should not cause errors
        let rule = CharsetRegistered;
        let cfg = make_cfg();
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-type",
            "text/plain; charset=utf-8;",
        )]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn duplicate_charset_param_reports_violation() {
        let rule = CharsetRegistered;
        let cfg = make_cfg();
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-type",
            "text/plain; charset=utf-8; charset=unknown-charset",
        )]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn parse_allowed_config_missing_rule_errors() {
        let cfg = crate::config::Config::default();
        let res = CharsetRegistered.prepare(&cfg);
        assert!(res.is_err());
        let msg = res.unwrap_err().to_string();
        assert!(msg.contains("requires configuration") || msg.contains("missing"));
    }

    #[test]
    fn validate_parses_config() -> anyhow::Result<()> {
        let mut full_cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["charset_registered"]);
        full_cfg.rules.insert(
            "charset_registered".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(vec![toml::Value::String("utf-8".into())]),
                );
                t
            }),
        );

        let arc = CharsetRegistered.prepare(&full_cfg)?;
        let arc: &crate::helpers::rule_config::AllowedList =
            arc.state.downcast_ref().expect("allowed list state");
        assert!(arc.allowed.contains(&"utf-8".to_string()));
        Ok(())
    }

    #[test]
    fn obs_text_in_an_unquoted_charset_is_reported() {
        // This asserted `is_none()` under the name "non_utf8_header_values_are
        // _ignored" — the name was the claim and the claim was the defect. An
        // unquoted value must satisfy `token`, which admits no octet above
        // %x7F, so a bare obs-text byte here is not a charset name at all.
        let rule = CharsetRegistered;
        let cfg = make_cfg();

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let bad = HeaderValue::from_bytes(b"text/plain; charset=\xff").unwrap();
        tx.response
            .as_mut()
            .unwrap()
            .headers
            .insert("content-type", bad);

        let msg = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .expect("must be reported")
        .message;
        assert!(msg.contains("invalid character"), "{msg}");
    }

    #[test]
    fn id_and_scope_are_expected() {
        let rule = CharsetRegistered;
        assert_eq!(rule.id(), "charset_registered");
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }
}
