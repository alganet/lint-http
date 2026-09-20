// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};

pub struct MediaTypeSuffixValid;

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
use crate::violations::media_type::{
    MEDIA_TYPE_NAME_EMPTY, MEDIA_TYPE_SUFFIX_EMPTY, MEDIA_TYPE_SUFFIX_UNREGISTERED, RFC_6838_4_2,
    RFC_6838_4_2_8,
};
use crate::violations::ViolationDef;

/// Three, and two of them are mirrors: a `+` with nothing after it, a `+` with
/// nothing before it, and a suffix naming a structured syntax this deployment
/// does not know.
static DECLARED: &[&ViolationDef] = &[
    &MEDIA_TYPE_NAME_EMPTY,
    &MEDIA_TYPE_SUFFIX_EMPTY,
    &MEDIA_TYPE_SUFFIX_UNREGISTERED,
];
const RFC_9110_8_3_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("8.3.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3.1",
    note: "Media Type: the subtype a suffix lives in is case-insensitive, which is why suffixes are compared folded",
};
const IANA_MEDIA_TYPE_STRUCTURED_SUFFIXES: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "IANA Media Type Structured Suffixes",
    section: None,
    url: "https://www.iana.org/assignments/media-type-structured-suffix/media-type-structured-suffix.xhtml",
    note: "The registry this rule stands in for but does not read; the configured `allowed` array is what it actually checks against",
};

impl RuleMeta for MediaTypeSuffixValid {
    fn id(&self) -> &'static str {
        "media_type_suffix_valid"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
# Every name in IANA's Structured Syntax Suffix registry, read off the
# registry's own CSV rather than recalled -- a list that names a criterion is a
# claim about a set, and this one shipped six of the twenty-four. `+zip` has
# been registered since RFC 6839 and `application/epub+zip` is older than the
# registry itself, so the six-name list told an EPUB server that its suffix
# names a structured syntax nobody had registered, which is the opposite of the
# sentence the finding cites.
#
# The list also used to hold "exi" -- a name that registry has never held:
# "exi" is a registered HTTP *content coding* (W3C EXI), and it had been copied
# here from the neighbouring registry, silencing exactly the finding this rule
# exists to make for "+exi". Registry membership bounds this array in both
# directions.
#
# As with every allowed list, the registry is not consulted at lint time; this
# array stands in for it. So a suffix registered after this release reports
# until it is added here, and a deployment that serves one structured syntax
# may narrow the array to it.
allowed = ["ber", "cbor", "cbor-seq", "cose", "csv", "cwt", "der",
    "fastinfoset", "gzip", "jer", "json", "json-seq", "jws", "jwt",
    "sd-cwt", "sd-jwt", "sqlite3", "tlv", "uper", "wbxml", "xml", "yaml",
    "zip", "zstd"]
"#
    }

    fn prepare(&self, cfg: &crate::config::Config) -> anyhow::Result<crate::rules::ResolvedRule> {
        // Entries are folded once at prepare time rather than at every comparison;
        // the subtype a suffix lives in is case-insensitive, so the fold is the
        // matching rule.
        // cite(RFC 9110 § 8.3.1): "The type and subtype tokens are case-insensitive."
        let allowed = crate::helpers::rule_config::parse_lowercased_list(
            cfg,
            self.id(),
            "allowed",
            "known structured-syntax suffixes",
            "['json','xml']",
        )?;
        // The two standard keys, **after** this rule's own options, so a config
        // naming a bad option still fails on that option.
        crate::rules::validate_rule_table(cfg, self.id())?;
        Ok(crate::rules::ResolvedRule {
            state: Box::new(crate::helpers::rule_config::AllowedList { allowed }),
        })
    }

    fn title(&self) -> Option<&'static str> {
        Some("Media Type Suffix Validity")
    }

    fn description(&self) -> &'static str {
        "Flags media types — in `Content-Type` on either side of a transaction, or in any member of a request `Accept` — whose subtype ends in a `+suffix` that is not in the list you configure. A suffix names the structured syntax the payload is written in (`+json`, `+xml`), so a misspelled one is a claim about the payload that recipients cannot act on: RFC 6838 §4.2.8 says media types \"MUST NOT be given names incorporating suffixes for structured syntaxes they do not actually employ\", and that \"+suffix constructs for as-yet unregistered structured syntaxes SHOULD NOT be used\". A subtype ending in a bare `+` is reported too — it appends nothing and so names no syntax — as is one that is *only* a suffix (`application/+json`), which has no base name for the suffix to qualify.\n\n**It does not consult the IANA registry**, despite what its SpecRef points at: there is no lookup, and a suffix is \"registered\" as far as this rule is concerned exactly when your `allowed` array covers it. Comparison is case-insensitive, because the subtype a suffix lives in is.\n\n**Scope:** only the suffix, and only on a subtype that is a well-formed name. Whether the media type parses at all, whether the subtype's characters are legal, and whether more than one `Content-Type` field line is present are all `content_type_valid`'s findings; whether the full media type is one you allow is `content_type_registered`'s. A subtype carrying characters no name may contain is skipped here rather than reported as a bad suffix — that would name the wrong defect, and say it twice."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            RFC_6838_4_2_8,
            RFC_6838_4_2,
            RFC_9110_8_3_1,
            IANA_MEDIA_TYPE_STRUCTURED_SUFFIXES,
        ]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    /// **Three readings, two writers.** The request's `Content-Type` and its
    /// `Accept` members are the client's media types; the response's
    /// `Content-Type` is the origin's. A suffix defect belongs to whoever spelled
    /// the subtype it hangs off.
    ///
    /// Suffixes are read from Content-Type, which describes the representation a
    /// message carries, and from Accept, which is request-only — so the request
    /// side sees strictly more than the response side.
    /// cite(RFC 9110 § 8.3): "The "Content-Type" header field indicates the media type of the associated representation: either the representation enclosed in the message content or the selected representation, as determined by the message semantics."
    fn party(&self) -> crate::rules::RuleParty {
        crate::rules::RuleParty::PerSite
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
            // Offered rather than served, because the media-type *allowlist*
            // is a separate question from the suffix and it reads
            // `Content-Type` only. `application/epub+zip` is not on the
            // shipped `content_type_registered` array — that array is what a
            // deployment serves — and putting the suffix claim in an `Accept`
            // member keeps this example about the one thing it demonstrates.
            Example {
                compliance: Compliance::Compliant,
                label: Some("(+zip — a registered suffix outside the two common ones)"),
                snippet: "GET / HTTP/1.1\nHost: example.com\nAccept: application/epub+zip",
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

impl Rule for MediaTypeSuffixValid {
    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        // Each section is read on its own and the finding it yields is kept. The
        // media types a request is willing to accept are not the one a response
        // returns, and an unrecognized structured syntax suffix in each is two
        // peers' defects. Within a section the first offending value is still
        // the one reported.
        let mut out = Vec::new();
        {
            let config: &crate::helpers::rule_config::AllowedList = ctx.state();
            let check_media = |hdr_name: &str,
                               val: &str,
                               party: crate::lint::Party|
             -> Option<Violation> {
                // A value that is not a media-type has no subtype to inspect, and
                // saying so is `content_type_valid`'s finding. The
                // `media-type` grammar is the helper's.
                let parsed = match crate::helpers::media_type::parse_media_type(val) {
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
                if let Some(suffix) = crate::helpers::media_type::media_type_subtype_suffix(subtype)
                {
                    // A subtype that is *only* a suffix has no base name to qualify,
                    // and `restricted-name-first` admits no "+". The mirror image of
                    // the bare-trailing-"+" check below, on the same reasoning.
                    // cite(RFC 6838 § 4.2): "restricted-name = restricted-name-first *126restricted-name-chars restricted-name-first  = ALPHA / DIGIT"
                    if subtype.starts_with('+') {
                        return Some(ctx.by(party).report_with(&MEDIA_TYPE_NAME_EMPTY, format!(
                                "Media type '{}/{}' in {} is a structured suffix with no base subtype name",
                                parsed.type_, parsed.subtype, hdr_name
                            )));
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
                        return Some(ctx.by(party).report_with(
                            &MEDIA_TYPE_SUFFIX_EMPTY,
                            format!(
                                "Media type '{}/{}' in {} has empty structured suffix",
                                parsed.type_, parsed.subtype, hdr_name
                            ),
                        ));
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
                        return Some(ctx.by(party).report_with(&MEDIA_TYPE_SUFFIX_UNREGISTERED, format!(
                                        "Unrecognized structured syntax suffix '+{}' in media type '{}/{}' (header '{}')",
                                        suffix, parsed.type_, parsed.subtype, hdr_name
                                    )));
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

            out.extend((|| -> Option<Violation> {
                for val in values(&tx.request.headers, "content-type") {
                    if let Some(v) = check_media("Content-Type", &val, crate::lint::Party::Client) {
                        return Some(v);
                    }
                }
                None
            })());

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
            //
            // One finding per member, because each is a media type the sender
            // named on its own terms: `Accept: application/vnd.x+,
            // application/y+zzz` names two suffixes the recipient cannot resolve
            // and used to draw one, leaving the second to be met on the next run.
            for ah in values(&tx.request.headers, "accept") {
                for part in crate::helpers::list::split_commas_respecting_quotes(&ah) {
                    let p = part;
                    if p.is_empty() {
                        continue;
                    }
                    out.extend(check_media("Accept", p, crate::lint::Party::Client));
                }
            }

            if let Some(resp) = &tx.response {
                out.extend((|| -> Option<Violation> {
                    for val in values(&resp.headers, "content-type") {
                        if let Some(v) =
                            check_media("Content-Type", &val, crate::lint::Party::Server)
                        {
                            return Some(v);
                        }
                    }
                    None
                })());
            }
        }
        out
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &MediaTypeSuffixValid;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// The names the shipped default carries, parsed out of `config_example()`
    /// rather than retyped: a second copy of this list is a second thing to
    /// drift, which is the defect the list itself had.
    fn shipped_default_suffixes() -> Vec<String> {
        let cfg: toml::Table = toml::from_str(MediaTypeSuffixValid.config_example())
            .expect("the shipped config example is TOML");
        cfg.get("allowed")
            .expect("the shipped config example sets `allowed`")
            .as_array()
            .expect("`allowed` is an array")
            .iter()
            .map(|v| {
                v.as_str()
                    .expect("every entry is a string")
                    .to_ascii_lowercase()
            })
            .collect()
    }

    /// The list's comment states a criterion — membership of IANA's Structured
    /// Syntax Suffix registry — so the list is a claim about a set. It had
    /// drifted to six of the twenty-four, and each name here was registered
    /// while the shipped default reported it as unregistered. `+zip` is the
    /// one that shows the cost: `application/epub+zip` has been a registered
    /// media type since 2007 and drew a `warn` citing a SHOULD about *as-yet
    /// unregistered* syntaxes.
    #[rstest]
    #[case("zip")]
    #[case("cbor")]
    #[case("cbor-seq")]
    #[case("gzip")]
    #[case("json-seq")]
    #[case("jwt")]
    #[case("jws")]
    #[case("sqlite3")]
    #[case("tlv")]
    #[case("yaml")]
    #[case("zstd")]
    #[case("cose")]
    #[case("cwt")]
    #[case("sd-jwt")]
    #[case("sd-cwt")]
    #[case("csv")]
    #[case("uper")]
    #[case("jer")]
    fn the_default_list_carries_the_registered_suffix(#[case] name: &str) {
        assert!(
            shipped_default_suffixes().iter().any(|s| s == name),
            "`+{}` is in the registry the list names and is not on it",
            name
        );
    }

    /// The other half of the same claim, and the half a list can only get
    /// wrong by growing. `exi` is the recorded case: a registered HTTP
    /// *content coding*, copied here from the neighbouring registry, which
    /// silenced the finding this rule exists to make for `+exi`.
    #[rstest]
    #[case("exi")]
    #[case("br")]
    #[case("deflate")]
    #[case("identity")]
    #[case("pack200-gzip")]
    fn the_default_list_omits_the_name_that_is_not_a_suffix(#[case] name: &str) {
        assert!(
            !shipped_default_suffixes().iter().any(|s| s == name),
            "`{}` is not in the Structured Syntax Suffix registry and is on the list",
            name
        );
    }

    /// The array is only a claim until the rule reads it. Judged through the
    /// shipped default rather than a hand-built one: a registered suffix draws
    /// nothing, and a name no registry holds still draws the finding — which
    /// is the direction widening a list can break.
    #[rstest]
    #[case("application/epub+zip", false)]
    #[case("application/senml+cbor", false)]
    #[case("application/vnd.oai.openapi+yaml", false)]
    #[case("application/oauth-authz-req+jwt", false)]
    #[case("application/vnd.example+json-seq", false)]
    #[case("application/ld+json", false)]
    #[case("application/vnd.example+exi", true)]
    #[case("application/vnd.example+nope", true)]
    fn the_shipped_default_judges_the_content_type(#[case] value: &str, #[case] reported: bool) {
        let rule = MediaTypeSuffixValid;
        let mut cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["media_type_suffix_valid"]);
        let example: toml::Table =
            toml::from_str(rule.config_example()).expect("the shipped config example is TOML");
        cfg.rules.insert(
            "media_type_suffix_valid".into(),
            toml::Value::Table(example),
        );
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-type", value)],
        );
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert_eq!(
            v.as_ref()
                .is_some_and(|v| v.violation == "media_type_suffix_unregistered"),
            reported,
            "{value} -> {v:?}"
        );
    }

    /// The count, so a name added without reading the registry fails here
    /// rather than passing both halves above.
    #[test]
    fn the_default_list_is_the_whole_registry() {
        let got = shipped_default_suffixes();
        assert_eq!(
            got.len(),
            24,
            "the registry held 24 names when this was read; got {got:?}"
        );
        let mut sorted = got.clone();
        sorted.sort();
        assert_eq!(got, sorted, "the list is kept sorted so a diff is readable");
    }

    /// **Every media type the request offered is answered.** `Accept` is a list
    /// and each member is a type the sender named on its own terms, so two
    /// suffixes the recipient cannot resolve are two things to correct.
    #[test]
    fn every_defective_suffix_in_accept_is_reported() {
        let rule = MediaTypeSuffixValid;
        let mut cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["media_type_suffix_valid"]);
        cfg.rules.insert(
            "media_type_suffix_valid".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(vec![toml::Value::String("json".into())]),
                );
                t
            }),
        );
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "accept",
            "application/vnd.x+, application/y+zzz, application/z+json",
        )]);
        let found = crate::test_helpers::run_rule_all(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        let ids: Vec<_> = found.iter().map(|v| v.violation.as_str()).collect();
        assert!(ids.contains(&"media_type_suffix_empty"), "{ids:?}");
        assert!(ids.contains(&"media_type_suffix_unregistered"), "{ids:?}");
    }

    /// Every published snippet is run through this rule and, for the Compliant
    /// ones, through the other rules that read the same headers — judged against
    /// `config_example.toml`, so the allowlists are the ones a reader has.
    /// Nothing else does this, and four families have now shipped a Compliant
    /// example a sibling rejects.
    #[test]
    fn published_examples_survive_the_other_media_type_rules() {
        use crate::rules::{Compliance, RuleMeta as _};
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
        let v = v.unwrap();
        assert_eq!(v.violation, "media_type_suffix_unregistered");
        assert!(v.message.contains("+unknown"));
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
        let v = v.unwrap();
        assert_eq!(v.violation, "media_type_suffix_empty");
        assert!(v.message.contains("empty structured suffix"));
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

    /// The three entries, and which shape each answers for — the two mirrors
    /// around the `+` and the suffix nobody registered.
    #[rstest]
    #[case("application/+json", "media_type_name_empty")]
    #[case("application/vnd.example+", "media_type_suffix_empty")]
    #[case("application/vnd.example+nope", "media_type_suffix_unregistered")]
    fn each_shape_names_its_entry(#[case] value: &str, #[case] id: &str) {
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-type", value)],
        );
        let v = crate::test_helpers::run_rule(
            &MediaTypeSuffixValid,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &make_cfg(),
        )
        .unwrap_or_else(|| panic!("expected a finding for {value}"));
        assert_eq!(v.violation, id, "{}", v.message);
    }

    #[test]
    fn needs_no_response() {
        let rule = MediaTypeSuffixValid;
        assert!(!rule.needs_response());
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
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(vec![toml::Value::String("ldjson".into())]),
                );
                t
            }),
        );

        let parsed = MediaTypeSuffixValid.prepare(&cfg)?;
        let parsed: &crate::helpers::rule_config::AllowedList =
            parsed.state.downcast_ref().expect("allowed list state");
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
                t.insert("allowed".into(), toml::Value::Array(vec![]));
                t
            }),
        );

        let res = MediaTypeSuffixValid.prepare(&cfg);
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
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(vec![toml::Value::Integer(1)]),
                );
                t
            }),
        );

        let res = MediaTypeSuffixValid.prepare(&cfg);
        assert!(res.is_err());
    }

    #[test]
    fn parse_config_requires_allowed_array() {
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["media_type_suffix_valid"]);
        let res = MediaTypeSuffixValid.prepare(&cfg);
        assert!(res.is_err());
    }

    #[test]
    fn validate_parses_config() -> anyhow::Result<()> {
        let mut full_cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["media_type_suffix_valid"]);
        full_cfg.rules.insert(
            "media_type_suffix_valid".into(),
            toml::Value::Table({
                let mut t = toml::map::Map::new();
                t.insert("enabled".into(), toml::Value::Boolean(true));
                t.insert(
                    "allowed".into(),
                    toml::Value::Array(vec![toml::Value::String("json".into())]),
                );
                t
            }),
        );

        let arc = MediaTypeSuffixValid.prepare(&full_cfg)?;
        let arc: &crate::helpers::rule_config::AllowedList =
            arc.state.downcast_ref().expect("allowed list state");
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
