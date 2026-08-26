// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

pub struct MediaTypeSuffixValid;

#[derive(Debug, Clone)]
pub struct MessageMediaTypeSuffixConfig {
    pub severity: crate::lint::Severity,
    pub allowed: Vec<String>,
}

fn parse_allowed_config(
    config: &crate::config::Config,
    rule_id: &str,
) -> anyhow::Result<MessageMediaTypeSuffixConfig> {
    let severity = crate::rules::get_rule_severity_required(config, rule_id)?;

    let rule_cfg = config
        .get_rule_config(rule_id)
        .ok_or_else(|| anyhow::anyhow!("missing configuration for '{}'", rule_id))?;
    let table = rule_cfg
        .as_table()
        .ok_or_else(|| anyhow::anyhow!("Configuration for rule '{}' must be a table", rule_id))?;

    let allowed_val = table.get("allowed").ok_or_else(|| {
                anyhow::anyhow!(
                    "Rule '{}' requires an 'allowed' array listing known structured-syntax suffixes (e.g., ['json','xml'])",
                    rule_id
                )
            })?;

    let arr = allowed_val.as_array().ok_or_else(|| {
        anyhow::anyhow!("'allowed' must be an array of strings (e.g., ['json','xml'])")
    })?;

    if arr.is_empty() {
        return Err(anyhow::anyhow!("'allowed' array cannot be empty"));
    }

    // Folded once here rather than at every comparison; the subtype a suffix
    // lives in is case-insensitive, so the fold is the matching rule.
    // cite(RFC 9110 § 8.3.1): "The type and subtype tokens are case-insensitive."
    let mut out = Vec::new();
    for (i, item) in arr.iter().enumerate() {
        let s = item.as_str().ok_or_else(|| {
            anyhow::anyhow!("'allowed' array item at index {} must be a string", i)
        })?;
        out.push(s.to_ascii_lowercase());
    }

    Ok(MessageMediaTypeSuffixConfig {
        severity,
        allowed: out,
    })
}

impl Rule for MediaTypeSuffixValid {
    fn id(&self) -> &'static str {
        "media_type_suffix_valid"
    }

    // Suffixes are read from Content-Type, which describes the representation a
    // message carries, and from Accept, which is request-only — so the request
    // side sees strictly more than the response side.
    // cite(RFC 9110 § 8.3): "The "Content-Type" header field indicates the media type of the associated representation: either the representation enclosed in the message content or the selected representation, as determined by the message semantics."
    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn prepare(&self, cfg: &crate::config::Config) -> anyhow::Result<crate::rules::ResolvedRule> {
        let config = parse_allowed_config(cfg, self.id())?;
        // The two standard keys, **after** this rule's own options, so a config
        // naming a bad option still fails on that option.
        crate::rules::validate_rule_table(cfg, self.id())?;
        Ok(crate::rules::ResolvedRule {
            severity: config.severity,
            state: Box::new(config),
        })
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Option<Violation> {
        let config: &MessageMediaTypeSuffixConfig = ctx.state();
        let check_media = |hdr_name: &str, val: &str| -> Option<Violation> {
            // A value that is not a media-type has no subtype to inspect, and
            // saying so is `content_type_valid`'s finding. The
            // `media-type` grammar is the helper's.
            let parsed = match crate::helpers::headers::parse_media_type(val) {
                Ok(p) => p,
                Err(_) => return None,
            };
            // Not trimmed again. `parse_media_type` has already excluded the
            // `OWS` its production prints, and it prints none inside
            // `type "/" subtype` — so a second `str::trim` here removed nothing
            // legal and, on a value read one `char` per octet, removed %xA0 from
            // a malformed subtype and left this rule judging the suffix of a
            // name that is not well formed. That is the finding its own
            // `description()` promises to leave to the rule that owns it.
            // cite(RFC 9110 § 8.3.1, label: media-type grammar): "media-type = type "/" subtype parameters"
            let subtype = parsed.subtype;

            // `parse_media_type` is structural — it finds the "/" and checks that
            // neither half is empty — so a subtype full of characters no subtype
            // may contain still arrives here. Judging its *suffix* would name the
            // wrong defect and would say it twice, since
            // `content_type_valid` already reports the subtype. A
            // suffix question only arises once there is a well-formed name to
            // hang it on.
            //
            // `restricted-name` is stricter than `token`, but `token` is the
            // shared predicate this catalogue has, and the two agree on
            // everything that matters here: neither admits obs-text, whitespace,
            // or a separator. Erring toward `token` keeps the rule from
            // adjudicating subtype spelling, which is not its job.
            // cite(RFC 6838 § 4.2): "Type and subtype names MUST conform to the following ABNF:"
            if crate::helpers::token::find_invalid_token_char(subtype).is_some() {
                return None;
            }

            // Which "+" starts the suffix is not a matter of inference: the ABNF
            // says it in the comment on its own production, which is what the
            // helper's `rfind('+')` encodes. A base name may itself contain "+".
            // cite(RFC 6838 § 4.2): "restricted-name-chars =/ "+" ; Characters after last plus always ; specify a structured syntax suffix"
            if let Some(suffix) = crate::helpers::headers::media_type_subtype_suffix(subtype) {
                // A subtype that is *only* a suffix has no base name to qualify,
                // and `restricted-name-first` admits no "+". The mirror image of
                // the bare-trailing-"+" check below, on the same reasoning.
                // cite(RFC 6838 § 4.2): "restricted-name = restricted-name-first *126restricted-name-chars restricted-name-first  = ALPHA / DIGIT"
                if subtype.starts_with('+') {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!(
                            "Media type '{}/{}' in {} is a structured suffix with no base subtype name",
                            parsed.type_, parsed.subtype, hdr_name
                        ),
                    });
                }
                // Suffixes are compared folded because the subtype they sit in
                // is case-insensitive; `+JSON` is the same suffix as `+json`.
                // cite(RFC 9110 § 8.3.1): "The type and subtype tokens are case-insensitive."
                let suffix = suffix.to_ascii_lowercase();
                // A trailing "+" appends nothing, so it names no structured
                // syntax. `restricted-name-chars` admits "+" anywhere after the
                // first character, so the grammar permits this shape; the
                // reading is the construct's purpose, as above.
                if suffix.is_empty() {
                    return Some(Violation {
                        rule: self.id().into(),
                        severity: config.severity,
                        message: format!(
                            "Media type '{}/{}' in {} has empty structured suffix",
                            parsed.type_, parsed.subtype, hdr_name
                        ),
                    });
                }

                // The sentence that actually governs this check. The one that
                // stood here before — "media types … SHOULD use the appropriate
                // registered "+suffix" … when they are registered" — is about
                // choosing a suffix at *registration* time, not about using an
                // unregistered one on the wire, which is what a linter sees. The
                // MUST NOT beside it is the sharper half of the same paragraph
                // and explains why a wrong suffix is worth reporting at all: it
                // is a claim about the payload's structure.
                //
                // As with every `allowed` list in this catalogue, the registry
                // is not consulted — the operator's array stands in for it.
                // cite(RFC 6838 § 4.2.8): ""+suffix" constructs for as-yet unregistered structured syntaxes SHOULD NOT be used, given the possibility of conflicts with future suffix definitions."
                // cite(RFC 6838 § 4.2.8): "By the same token, media types MUST NOT be given names incorporating suffixes for structured syntaxes they do not actually employ."
                if !config.allowed.contains(&suffix) {
                    return Some(Violation {
                                rule: self.id().into(),
                                severity: config.severity,
                                message: format!(
                                    "Unrecognized structured syntax suffix '+{}' in media type '{}/{}' (header '{}')",
                                    suffix, parsed.type_, parsed.subtype, hdr_name
                                ),
                            });
                }
            }
            None
        };

        // Every field line, and decoded from the raw octets. `get_header_str`
        // does neither: it returns the first value and gives up entirely on a
        // value `to_str` refuses. Both losses are silent here, and both hide the
        // exact thing this rule looks for —
        //
        //   Content-Type: application/json
        //   Content-Type: application/vnd.x+bogus
        //
        // reported nothing, and so did a bad suffix sitting next to a parameter
        // carrying obs-text, which is legal in a `quoted-string`.
        // cite(RFC 9110 § 5.5): "A recipient SHOULD treat other allowed octets in field content (i.e., obs-text) as opaque data."
        let values = |headers: &hyper::HeaderMap, name: &'static str| -> Vec<String> {
            headers
                .get_all(name)
                .iter()
                .map(crate::helpers::headers::field_line_as_written)
                .collect()
        };

        for val in values(&tx.request.headers, "content-type") {
            if let Some(v) = check_media("Content-Type", &val) {
                return Some(v);
            }
        }

        // Accept is a list, so each member is checked. Each field line is split
        // on its own rather than after recombining them, which is *not* the same
        // thing: an unbalanced quote in one line would otherwise swallow the
        // members of every line after it. Splitting per line confines that
        // damage to the line that carries the typo.
        //
        // Quote-aware, because a comma inside a quoted parameter value is not a
        // list separator. A raw `split(',')` cut such a value apart and then
        // read the pieces as media types, so text that merely looks like one
        // was reported as a real media type with a bad suffix:
        //
        //   Accept: application/json;p="a,foo/bar+bogus"
        //   -> Unrecognized structured syntax suffix '+bogus"' in 'foo/bar+bogus"'
        //
        // The message even carried the stray quote, which is the tell.
        for ah in values(&tx.request.headers, "accept") {
            for part in crate::helpers::headers::split_commas_respecting_quotes(&ah) {
                let p = part;
                if p.is_empty() {
                    continue;
                }
                if let Some(v) = check_media("Accept", p) {
                    return Some(v);
                }
            }
        }

        if let Some(resp) = &tx.response {
            for val in values(&resp.headers, "content-type") {
                if let Some(v) = check_media("Content-Type", &val) {
                    return Some(v);
                }
            }
        }

        None
    }

    fn title(&self) -> Option<&'static str> {
        Some("Media Type Suffix Validity")
    }

    fn description(&self) -> &'static str {
        "Flags media types — in `Content-Type` on either side of a transaction, or in any member of a request `Accept` — whose subtype ends in a `+suffix` that is not in the list you configure. A suffix names the structured syntax the payload is written in (`+json`, `+xml`), so a misspelled one is a claim about the payload that recipients cannot act on: RFC 6838 §4.2.8 says media types \"MUST NOT be given names incorporating suffixes for structured syntaxes they do not actually employ\", and that \"+suffix constructs for as-yet unregistered structured syntaxes SHOULD NOT be used\". A subtype ending in a bare `+` is reported too — it appends nothing and so names no syntax — as is one that is *only* a suffix (`application/+json`), which has no base name for the suffix to qualify.\n\n**It does not consult the IANA registry**, despite what its SpecRef points at: there is no lookup, and a suffix is \"registered\" as far as this rule is concerned exactly when your `allowed` array covers it. Comparison is case-insensitive, because the subtype a suffix lives in is.\n\n**Scope:** only the suffix, and only on a subtype that is a well-formed name. Whether the media type parses at all, whether the subtype's characters are legal, and whether more than one `Content-Type` field line is present are all `content_type_valid`'s findings; whether the full media type is one you allow is `content_type_registered`'s. A subtype carrying characters no name may contain is skipped here rather than reported as a bad suffix — that would name the wrong defect, and say it twice."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 6838",
                section: Some("4.2.8"),
                url: "https://www.rfc-editor.org/rfc/rfc6838.html#section-4.2.8",
                note: "Structured Syntax Name Suffixes: that an unregistered `+suffix` SHOULD NOT be used, and — the sharper half — that a suffix MUST NOT name a syntax the type does not employ",
            },
            crate::rules::SpecRef {
                spec: "RFC 6838",
                section: Some("4.2"),
                url: "https://www.rfc-editor.org/rfc/rfc6838.html#section-4.2",
                note: "Naming Requirements: `restricted-name`, which decides where a suffix starts (\"characters after last plus\") and that a name must begin with ALPHA or DIGIT — so a subtype that is only a suffix has no base name",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("8.3.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3.1",
                note: "Media Type: the subtype a suffix lives in is case-insensitive, which is why suffixes are compared folded",
            },
            crate::rules::SpecRef {
                spec: "IANA Media Type Structured Suffixes",
                section: None,
                url: "https://www.iana.org/assignments/media-type-structured-suffix/media-type-structured-suffix.xhtml",
                note: "The registry this rule stands in for but does not read; the configured `allowed` array is what it actually checks against",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            // One message per example. These were two blocks of stacked
            // `Content-Type:` lines meaning "any of these" — a reading
            // `content_type_valid` now contradicts, since two
            // Content-Type lines in one message are themselves a defect.
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nContent-Type: application/ld+json",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(+xml)"),
                snippet: "HTTP/1.1 200 OK\nContent-Type: image/svg+xml",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(Accept member)"),
                snippet:
                    "GET / HTTP/1.1\nHost: example.com\nAccept: application/vnd.example+json; q=0.8",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(unknown suffix)"),
                snippet: "HTTP/1.1 200 OK\nContent-Type: application/vnd.example+unknown",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(unknown suffix in an Accept member)"),
                snippet: "GET / HTTP/1.1\nHost: example.com\nAccept: application/bar+nope",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(a bare `+` appends nothing)"),
                snippet: "HTTP/1.1 200 OK\nContent-Type: application/vnd.example+",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &MediaTypeSuffixValid;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// Every published snippet is run through this rule and, for the Compliant
    /// ones, through the other rules that read the same headers — judged against
    /// `config_example.toml`, so the allowlists are the ones a reader has.
    /// Nothing else does this, and four families have now shipped a Compliant
    /// example a sibling rejects.
    #[test]
    fn published_examples_survive_the_other_media_type_rules() {
        use crate::rules::{Compliance, Rule as _};
        let rule = MediaTypeSuffixValid;
        let toml_src = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../config_example.toml"),
        )
        .expect("config_example.toml must be readable");
        let cfg: crate::config::Config =
            toml::from_str(&toml_src).expect("config_example.toml must parse");
        let siblings: [(&str, &dyn Rule); 5] = [
            (
                "well-formed",
                &crate::rules::content_type_valid::ContentTypeValid,
            ),
            (
                "media-type allowlist",
                &crate::rules::content_type_registered::ContentTypeRegistered,
            ),
            (
                "charset presence",
                &crate::rules::charset_present::CharsetPresent,
            ),
            (
                "nosniff",
                &crate::rules::x_content_type_options_present::XContentTypeOptionsPresent,
            ),
            (
                "header-name allowlist",
                &crate::rules::extension_headers_registered::ExtensionHeadersRegistered,
            ),
        ];

        for ex in rule.examples() {
            let mut pairs: Vec<(&str, &str)> = Vec::new();
            // One predicate for "this is the start-line", used both to skip it
            // and to decide which half of the transaction the example is. Two
            // different tests would let a request-line the skip missed reach
            // the header parser, or a response be fed in as a request.
            let is_status_line = |l: &str| l.starts_with("HTTP/");
            let is_request_line = |l: &str| l.contains(" HTTP/");
            for line in ex.snippet.lines() {
                if is_status_line(line) || is_request_line(line) || line.is_empty() {
                    continue;
                }
                let (k, v) = line.split_once(": ").unwrap_or_else(|| {
                    panic!("example header line is not `Name: value`: {line:?}")
                });
                pairs.push((k, v));
            }
            assert!(!pairs.is_empty(), "example has no headers: {}", ex.snippet);

            let on_response = ex.snippet.lines().next().is_some_and(is_status_line);
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
                    // `v.rule` is always this rule's id — the rule only ever
                    // builds violations with `self.id()` — so asserting that
                    // says nothing. What is worth pinning is that the example
                    // fails for the reason it illustrates.
                    let v = v.unwrap_or_else(|| {
                        panic!("rule accepts its NonCompliant example {:?}", ex.snippet)
                    });
                    assert!(
                        v.message.contains("suffix"),
                        "NonCompliant example {:?} fails for an unrelated reason: {v:?}",
                        ex.snippet
                    );
                }
            }
        }
    }

    #[rstest]
    // A subtype that is not a well-formed name is `content_type_valid`'s
    // finding, not a suffix question. Before the token gate these were reported
    // here as bad *suffixes*, naming the wrong defect and saying it twice.
    #[case(b"application/ld+json\xe4", false)]
    #[case("application/ld+jso\u{ad}n".as_bytes(), false)]
    // %xA0 is the one the second trim reached. `parse_media_type` has already
    // excluded the `OWS` its production prints and prints none inside
    // `type "/" subtype`, so the extra `str::trim` this rule ran took an
    // `obs-text` octet off a malformed subtype and then judged its suffix —
    // reporting `+bogus` about a name that is not a name.
    #[case(b"application/vnd.x+bogus\xA0", false)]
    #[case(b"application/vnd.x+json\xA0", false)]
    // A subtype that is only a suffix has no base name to qualify.
    #[case(b"application/+json", true)]
    // Well-formed names are still judged on their suffix.
    #[case(b"application/ld+json", false)]
    #[case(b"application/vnd.x+bogus", true)]
    #[case(b"application/vnd.x+", true)]
    fn only_well_formed_subtypes_are_judged_on_their_suffix(
        #[case] raw: &[u8],
        #[case] expect: bool,
    ) {
        use hyper::header::HeaderValue;
        let rule = MediaTypeSuffixValid;
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
            expect,
            "{:?} -> {v:?}",
            String::from_utf8_lossy(raw)
        );

        // The malformed subtypes are not silent overall: the rule that owns
        // subtype syntax reports them.
        if !expect && String::from_utf8_lossy(raw).contains(char::REPLACEMENT_CHARACTER)
            || raw.contains(&0xc2)
        {
            let sib_cfg =
                crate::test_helpers::make_test_config_with_enabled_rules(&["content_type_valid"]);
            let other = crate::test_helpers::run_rule(
                &crate::rules::content_type_valid::ContentTypeValid,
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &sib_cfg,
            );
            assert!(other.is_some(), "unreported by both rules");
        }
    }

    #[rstest]
    // A comma inside a quoted parameter value is not a list separator, so the
    // text after it is not a media type and must not be judged as one.
    #[case("application/json;p=\"a,foo/bar+bogus\"", false)]
    #[case("application/json;p=\"x,y/z+nope\", text/html", false)]
    // Real members are still each checked, before and after a quoted comma.
    #[case("text/html, application/vnd.x+bogus", true)]
    #[case("application/json;p=\"a,b\", application/vnd.x+bogus", true)]
    #[case("application/ld+json, text/html", false)]
    fn accept_members_split_on_real_commas_only(#[case] accept: &str, #[case] expect: bool) {
        let rule = MediaTypeSuffixValid;
        let cfg = make_cfg();
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[("accept", accept)]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert_eq!(v.is_some(), expect, "{accept} -> {v:?}");
    }

    #[rstest]
    // A bad suffix on a second Content-Type line: `get_header_str` stopped at
    // the first and reported nothing.
    #[case(&["application/json", "application/vnd.x+bogus"], true)]
    #[case(&["application/vnd.x+bogus", "application/json"], true)]
    #[case(&["application/json", "application/ld+json"], false)]
    fn every_content_type_line_is_checked(#[case] values: &[&str], #[case] expect: bool) {
        let rule = MediaTypeSuffixValid;
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
        assert_eq!(v.is_some(), expect, "{values:?} -> {v:?}");
    }

    #[rstest]
    // obs-text is legal in a quoted parameter value, so these are well-formed
    // media types whose suffix still has to be judged. `to_str` refused them
    // and the rule went silent.
    #[case(b"application/vnd.x+bogus; p=\"\xe4\"", true)]
    #[case(b"application/ld+json; p=\"\xe4\"", false)]
    fn obs_text_does_not_hide_the_suffix(#[case] raw: &[u8], #[case] expect: bool) {
        use hyper::header::HeaderValue;
        let rule = MediaTypeSuffixValid;
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
            expect,
            "{:?} -> {v:?}",
            String::from_utf8_lossy(raw)
        );
    }

    fn make_cfg() -> crate::config::Config {
        let mut cfg = crate::config::Config::default();
        cfg.rules.insert(
            "media_type_suffix_valid".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(vec![
                        toml::Value::String("json".into()),
                        toml::Value::String("xml".into()),
                        toml::Value::String("ber".into()),
                        toml::Value::String("der".into()),
                        toml::Value::String("fastinfoset".into()),
                        toml::Value::String("wbxml".into()),
                        toml::Value::String("exi".into()),
                    ]),
                );
                t
            }),
        );
        cfg
    }

    #[rstest]
    fn valid_application_ld_json() {
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-type", "application/ld+json")],
        );
        let rule = MediaTypeSuffixValid;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &make_cfg(),
        );
        assert!(v.is_none());
    }

    #[rstest]
    fn invalid_content_type_suffix() {
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-type", "application/vnd.example+unknown")],
        );
        let rule = MediaTypeSuffixValid;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &make_cfg(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("+unknown"));
    }

    #[rstest]
    fn accept_header_with_bad_suffix_reports_violation() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "accept",
            "application/vnd.foo+xml; q=0.8, application/bar+nope",
        )]);
        let rule = MediaTypeSuffixValid;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &make_cfg(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("+nope"));
    }

    #[rstest]
    fn detect_empty_suffix_reports_violation() {
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-type", "application/foo+")],
        );
        let rule = MediaTypeSuffixValid;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &make_cfg(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("empty structured suffix"));
    }

    #[rstest]
    fn uppercase_suffix_is_accepted() {
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-type", "application/ld+JSON")],
        );
        let rule = MediaTypeSuffixValid;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &make_cfg(),
        );
        assert!(v.is_none());
    }

    #[rstest]
    fn malformed_media_type_is_ignored() {
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-type", "text")],
        );
        let rule = MediaTypeSuffixValid;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &make_cfg(),
        );
        assert!(v.is_none());
    }

    #[rstest]
    fn request_content_type_bad_suffix_reports_violation() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-type",
            "application/vnd.foo+unknown",
        )]);
        let rule = MediaTypeSuffixValid;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &make_cfg(),
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("+unknown"));
    }

    #[rstest]
    fn request_content_type_uppercase_suffix_accepted() {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-type",
            "application/example+JSON",
        )]);
        let rule = MediaTypeSuffixValid;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &make_cfg(),
        );
        assert!(v.is_none());
    }

    #[rstest]
    fn accept_header_case_insensitive_suffix_accepted() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "accept",
            "application/vnd.foo+JSON; q=0.8, text/html",
        )]);
        let rule = MediaTypeSuffixValid;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &make_cfg(),
        );
        assert!(v.is_none());
    }

    #[test]
    fn scope_is_both() {
        let rule = MediaTypeSuffixValid;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Both);
    }

    #[test]
    fn parse_config_allows_custom_list() -> anyhow::Result<()> {
        let mut cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["media_type_suffix_valid"]);
        cfg.rules.insert(
            "media_type_suffix_valid".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(vec![toml::Value::String("ldjson".into())]),
                );
                t
            }),
        );

        let parsed = parse_allowed_config(&cfg, "media_type_suffix_valid")?;
        assert_eq!(parsed.allowed, vec!["ldjson".to_string()]);
        Ok(())
    }

    #[test]
    fn parse_config_rejects_empty_allowed_array() {
        let mut cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["media_type_suffix_valid"]);
        cfg.rules.insert(
            "media_type_suffix_valid".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert("allowed".into(), toml::Value::Array(vec![]));
                t
            }),
        );

        let res = parse_allowed_config(&cfg, "media_type_suffix_valid");
        assert!(res.is_err());
    }

    #[test]
    fn parse_config_rejects_non_string_allowed_item() {
        let mut cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["media_type_suffix_valid"]);
        cfg.rules.insert(
            "media_type_suffix_valid".into(),
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

        let res = parse_allowed_config(&cfg, "media_type_suffix_valid");
        assert!(res.is_err());
    }

    #[test]
    fn parse_config_requires_allowed_array() {
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["media_type_suffix_valid"]);
        let res = parse_allowed_config(&cfg, "media_type_suffix_valid");
        assert!(res.is_err());
    }

    #[test]
    fn validate_parses_config() -> anyhow::Result<()> {
        let rule = MediaTypeSuffixValid;
        let mut full_cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["media_type_suffix_valid"]);
        full_cfg.rules.insert(
            "media_type_suffix_valid".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert("severity".into(), toml::Value::String("warn".into()));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(vec![toml::Value::String("json".into())]),
                );
                t
            }),
        );

        let arc = parse_allowed_config(&full_cfg, rule.id())?;
        assert!(arc.allowed.contains(&"json".to_string()));
        Ok(())
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "media_type_suffix_valid");
        // Add required 'allowed' key
        if let Some(toml::Value::Table(t)) = cfg.rules.get_mut("media_type_suffix_valid") {
            t.insert(
                "allowed".to_string(),
                toml::Value::Array(vec![toml::Value::String("json".into())]),
            );
        }
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
