// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::Rule;

#[derive(Debug, Clone)]
pub struct MethodTokenConfig {
    pub enabled: bool,
    pub severity: crate::lint::Severity,
    pub registered_methods: Vec<String>,
}

/// Reads the `registered_methods` array this rule cannot supply for itself.
///
/// The convention this rule reports against is stated about *standardized* methods,
/// and the eight RFC 9110 defines are only the ones that document happens to define:
/// the rest are registered elsewhere, in an IANA registry that grows by IETF Review.
/// A list compiled in here would be a snapshot of that registry presented as though
/// it were the grammar -- and the grammar admits every one of the spellings this rule
/// reports, which is the whole reason the finding needs a set of names to lean on.
///
/// The array is also where a deployment writes down its own uppercase-by-convention
/// methods. A private `PURGE` is a method no registry knows, so `purge` draws nothing
/// until this array says the deployment expects to see that name.
// cite(RFC 9110 § 16.1.1): "The "Hypertext Transfer Protocol (HTTP) Method Registry", maintained by IANA at <https://www.iana.org/assignments/http-methods>, registers method names."
// cite(RFC 9110 § 16.1.1): "Values to be added to this namespace require IETF Review"
// cite(RFC 9110 § 9.1): "All such methods ought to be registered within the "Hypertext Transfer Protocol (HTTP) Method Registry", as described in Section 16.1."
fn parse_method_token_config(
    config: &crate::config::Config,
    rule_id: &str,
) -> anyhow::Result<MethodTokenConfig> {
    let severity = crate::rules::get_rule_severity_required(config, rule_id)?;
    let enabled = crate::rules::get_rule_enabled_required(config, rule_id)?;

    let rule_cfg = config.get_rule_config(rule_id).ok_or_else(|| {
        anyhow::anyhow!(
            "rule '{}' requires configuration and a named 'registered_methods' array listing the method names this deployment expects to see spelled as they are defined. Example in config_example.toml",
            rule_id
        )
    })?;
    let table = rule_cfg
        .as_table()
        .ok_or_else(|| anyhow::anyhow!("Configuration for rule '{}' must be a table", rule_id))?;

    let value = table.get("registered_methods").ok_or_else(|| {
        anyhow::anyhow!(
            "Rule '{}' requires a 'registered_methods' array listing standardized method names (e.g., ['GET','HEAD','POST','PUT'])",
            rule_id
        )
    })?;

    let arr = value.as_array().ok_or_else(|| {
        anyhow::anyhow!("'registered_methods' must be an array of strings (e.g., ['GET','HEAD'])")
    })?;

    // No sentence forbids an empty array. It is refused because the branch it feeds
    // would then be unreachable, and a rule that silently checks two of its three
    // questions reads as a linter that agrees rather than one that was switched off.
    //
    // Which is also why an absent or empty array stops the rule outright rather than
    // only the branch that reads it: the two grammar questions never touch these names,
    // so silencing just the third would leave a configuration error looking like a
    // clean run. A deployment that wants only the grammar half turns the rule off.
    if arr.is_empty() {
        return Err(anyhow::anyhow!(
            "'registered_methods' array cannot be empty"
        ));
    }

    let mut registered_methods = Vec::new();
    for (i, item) in arr.iter().enumerate() {
        let s = item.as_str().ok_or_else(|| {
            anyhow::anyhow!(
                "'registered_methods' array item at index {} must be a string",
                i
            )
        })?;
        // Kept exactly as written. These names are the spelling a request is measured
        // against, so folding them here would delete the difference the rule exists to
        // report.
        registered_methods.push(s.to_string());
    }

    Ok(MethodTokenConfig {
        enabled,
        severity,
        registered_methods,
    })
}

pub struct ClientRequestMethodTokenValid;

impl ClientRequestMethodTokenValid {
    fn violation(&self, config: &MethodTokenConfig, message: String) -> Violation {
        Violation {
            rule: self.id().into(),
            severity: config.severity,
            message,
        }
    }
}

impl Rule for ClientRequestMethodTokenValid {
    fn id(&self) -> &'static str {
        "client_request_method_token_valid"
    }

    /// Every sentence here is addressed to whoever generated the request, so the rule
    /// has to run on a request whose upstream never answered as well as on a complete
    /// exchange. `Client` is the scope that survives into the request-only dispatch;
    /// `Server` would skip exactly the captures where the request is all there is.
    // cite(RFC 9110 § 2.2): "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules."
    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Client
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        let m = tx.request.method.as_str();

        // The method is read for every HTTP version, and no gate narrows it, because
        // the production is written in the version-independent document and the two
        // multiplexed versions carry its result in a pseudo-header rather than in a
        // request-line. RFC 9112 § 3.1 is where an HTTP/1.1 message puts it.
        //
        // The production is quoted from the collected grammar, and it brings its
        // neighbour along: where § 9.1 prints it, it stands alone between two
        // paragraphs and is fourteen characters, below what a fragment can be.
        // cite(RFC 9110 § A): "method = token minute = 2DIGIT"
        // cite(RFC 9113 § 8.3.1): "The ":method" pseudo-header field includes the HTTP method (Section 9 of [HTTP])."
        // cite(RFC 9114 § 4.3.1): "":method":  Contains the HTTP method (Section 9 of [HTTP])"
        //
        // Nothing above the configuration read costs more than two scans of a token a
        // handful of octets long, and each of the three questions ends the rule on its
        // own. `parse_rule_config` is several map probes plus a hash over the rule id,
        // so only a request about to be reported pays it.
        let invalid_char = crate::helpers::token::find_invalid_token_char(m);
        // A string that is not a token has no case to be in yet: the character scan is
        // what decides whether this is a `method` at all, and the convention below is
        // about how a `method` naming a standardized one is spelled.
        let lowercase_in_token =
            invalid_char.is_none() && crate::helpers::token::find_first_lowercase(m).is_some();

        if !m.is_empty() && invalid_char.is_none() && !lowercase_in_token {
            return None;
        }

        let config = parse_method_token_config(cfg, self.id()).ok()?;

        // `token` is `1*tchar` -- one character at minimum, transcribed in full at
        // `helpers::token::is_tchar`. A character scan answers `None` for the empty
        // string because it finds no character to object to, so the cardinality is a
        // separate question and is asked here; three other readers of that helper say
        // the same thing in their own comments.
        if m.is_empty() {
            return Some(self.violation(
                &config,
                "Request carries an empty method token, and `method = token` has a one-character floor (`token = 1*tchar`), so the empty string derives from no production and names no method to apply to the target resource".into(),
            ));
        }

        // The grammar is what makes this a violation rather than an oddity: the
        // charset is a definition, and § 2.2 is the sentence that forbids generating
        // something outside it.
        // cite(RFC 9110 § 2.2): "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules."
        if let Some(c) = invalid_char {
            // Escaped, because the octet that fails a `tchar` test is very often one
            // that prints as nothing: a raw DEL interpolated here produced a finding
            // whose offending character was an empty pair of quotes.
            return Some(self.violation(
                &config,
                format!(
                    "Method token contains {}, which is not a `tchar`, so the request's method derives from no `token` and therefore from no `method`",
                    crate::helpers::headers::shown_in_finding(&c.to_string())
                ),
            ));
        }

        // Everything below is a `token` already, so it needs no escaping to be shown.
        //
        // The fold is the finding, not a comparison made with one: the question asked
        // is whether this token is a standardized method's name written in another
        // case, and folding is how that is asked. It is emphatically not a fold that
        // then applies that method's semantics -- the sentence beside it is why.
        // cite(RFC 9110 § 9.1): "The method token is case-sensitive because it might be used as a gateway to object-based systems with case-sensitive method names."
        // cite(RFC 9110 § 9.1): "By convention, standardized methods are defined in all-uppercase US-ASCII letters."
        if lowercase_in_token {
            let folded = m.to_ascii_uppercase();
            if config.registered_methods.iter().any(|r| r == &folded) {
                // What a recipient does with a token it cannot place is the reason this
                // is worth saying at all: the request does not fail to parse, it simply
                // asks for a method nobody defined.
                // cite(RFC 9110 § 9.1): "An origin server that receives a request method that is unrecognized or not implemented SHOULD respond with the 501 (Not Implemented) status code."
                return Some(self.violation(
                    &config,
                    format!(
                        "Method token '{m}' is '{folded}' written in another case. The method token is case-sensitive, so a server matching method names sees an unrecognized method here rather than '{folded}', and ought to answer 501 (Not Implemented); by convention a standardized method is defined in all-uppercase US-ASCII letters"
                    ),
                ));
            }
        }

        None
    }

    fn description(&self) -> &'static str {
        "Reports a request whose method token does not derive from `method = token` (RFC 9110 §9.1), and a request whose method is a standardized method's name written in a different case.\n\n**Two findings of different strengths.** A method token that is empty or carries a character outside `tchar` matches no production, and RFC 9110 §2.2 is what makes that a violation: \"A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules.\" The case finding rests on no requirement at all — §9.1 says only \"By convention, standardized methods are defined in all-uppercase US-ASCII letters\", which is a statement about how standards write their definitions, not one addressed to a sender.\n\n**What makes the case finding worth reporting is the sentence next to the convention.** §9.1: \"The method token is case-sensitive because it might be used as a gateway to object-based systems with case-sensitive method names.\" So `get` is not a badly typed `GET`; it is a method nothing defines, and §9.1 has an origin server answer an unrecognized method with `501 (Not Implemented)`. The finding is that a request asking for a standardized method will not get one.\n\n**Not reported: a lowercase method that is nobody's standardized method.** A deployment's private `x-purge` is a well-formed `token`, and the convention §9.1 states is about standardized methods — so there is no sentence under a report of it, and this rule used to make one anyway. `registered_methods` is what separates the two cases.\n\n**`registered_methods` is required, and the reason is that the names live in a registry.** RFC 9110 §16.1.1 registers method names at IANA and admits new ones by IETF Review; §9.1 says every method specified outside RFC 9110 \"ought to be registered\" there. The eight methods RFC 9110 defines are only the ones that document defines, so a list compiled into this rule would be a snapshot of an open registry presented as though it were the grammar. The array is also where a deployment records its own uppercase-by-convention names: add `PURGE` to it and `purge` is reported; leave it out and it is not.\n\n**A missing or empty array stops the whole rule, not only the case finding.** The two grammar questions never read these names, so silencing just the third would leave a configuration mistake looking like a clean run. A deployment that wants the grammar half and not the case advice disables the rule rather than emptying the array.\n\n**An incomplete array costs coverage and never a false report.** A name missing from it means one spelling goes unremarked — unlike the same shape in `message_early_data_header_safe_method`, where an absent name *is* the finding, because RFC 8470 §4 names \"methods whose safety is not known\" alongside the unsafe ones.\n\n**Every HTTP version is read, and there is no version gate.** `method = token` is written in the version-independent document; RFC 9112 §3.1 is where an HTTP/1.1 message carries the result, and RFC 9113 §8.3.1 and RFC 9114 §4.3.1 put the same value in a `:method` pseudo-header. `message_http2_pseudo_headers_validity` reports the `tchar` half a second time, on every version, because it carries no version gate of its own.\n\n**The two grammar findings do not arise in traffic this proxy captured.** A capture's method comes from `hyper::Method`, whose accepted character table is `tchar` exactly and which refuses a zero-length method, so a request that reaches the wire through this proxy cannot carry either defect. They are reachable in a capture written elsewhere and deserialized into the transaction model, which is the only reason the checks are here."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("9.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-9.1",
                note: "`method = token`, the token's case-sensitivity, the convention that standardized methods are defined in all-uppercase US-ASCII letters, and the 501 an origin server gives an unrecognized method",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("2.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-2.2",
                note: "The sentence that makes a value outside its ABNF a violation rather than an observation",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("5.6.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.2",
                note: "`token = 1*tchar`. The character set is transcribed once, in `helpers::token::is_tchar`; the `1*` floor is what the empty-method branch here reads",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("16.1.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-16.1.1",
                note: "The IANA method registry, which holds the names `registered_methods` is a deployment's copy of, and grows by IETF Review",
            },
            crate::rules::SpecRef {
                spec: "RFC 9112",
                section: Some("3.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9112.html#section-3.1",
                note: "Where an HTTP/1.1 message carries the method. This reference said §5.1, which is Field Line Parsing",
            },
            crate::rules::SpecRef {
                spec: "RFC 9113",
                section: Some("8.3.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9113.html#section-8.3.1",
                note: "The `:method` pseudo-header field, which is where an HTTP/2 request carries the same value",
            },
            crate::rules::SpecRef {
                spec: "RFC 9114",
                section: Some("4.3.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9114.html#section-4.3.1",
                note: "The `:method` pseudo-header field over HTTP/3",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("a standardized method, spelled as its definition spells it"),
                snippet: "GET /index.html HTTP/1.1",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some(
                    "a private method no registry knows: a well-formed token, and the convention §9.1 states is about standardized methods",
                ),
                snippet: "x-purge /cache/entry HTTP/1.1",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some(
                    "a standardized method's name in another case — the token is case-sensitive, so this asks for a method nobody defined",
                ),
                snippet: "get /index.html HTTP/1.1",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("`@` is not a `tchar`, so this method derives from no production"),
                snippet: "G@T /index.html HTTP/1.1",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &ClientRequestMethodTokenValid;

#[cfg(test)]
mod tests {
    use super::*;

    use rstest::rstest;

    /// The registry names the rule is exercised with. Kept short on purpose: the
    /// point under test is which set decides, not how complete a copy of the
    /// registry `config_example.toml` ships.
    const TEST_METHODS: &[&str] = &["GET", "POST", "PATCH", "PROPFIND"];

    fn config_with_methods(rule_id: &str, methods: &[&str]) -> crate::config::Config {
        let mut cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule_id]);
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert("severity".to_string(), toml::Value::String("warn".into()));
        table.insert(
            "registered_methods".to_string(),
            toml::Value::Array(
                methods
                    .iter()
                    .map(|m| toml::Value::String((*m).to_string()))
                    .collect(),
            ),
        );
        cfg.rules
            .insert(rule_id.to_string(), toml::Value::Table(table));
        cfg
    }

    fn check(method: &str) -> Option<Violation> {
        let rule = ClientRequestMethodTokenValid;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = method.to_string();
        rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config_with_methods(rule.id(), TEST_METHODS),
        )
    }

    #[rstest]
    #[case("GET", false)]
    #[case("POST", false)]
    #[case("G3T", false)]
    #[case("G-ET", false)]
    // The name is not built from `tchar`, whatever case it is in.
    #[case("G@T", true)]
    #[case("g@t", true)]
    // A standardized name in another case: the finding this rule keeps.
    #[case("gEt", true)]
    #[case("get", true)]
    #[case("patch", true)]
    #[case("propfind", true)]
    fn check_request_cases(#[case] method_str: &str, #[case] expect_violation: bool) {
        assert_eq!(check(method_str).is_some(), expect_violation);
    }

    /// A lowercase token that is nobody's standardized method rests on no sentence.
    /// This is the class the rule used to report: § 9.1's convention is stated about
    /// standardized methods, and a private one is not among them.
    #[rstest]
    #[case("x-purge")]
    #[case("frobnicate")]
    #[case("m")]
    fn a_private_lowercase_method_is_not_reported(#[case] method_str: &str) {
        assert!(check(method_str).is_none());
    }

    /// Adding a name to the array is how a deployment asks for its own convention to
    /// be checked -- the same token, reported or not, decided by the configuration.
    #[test]
    fn the_array_is_what_decides_a_private_methods_spelling() {
        let rule = ClientRequestMethodTokenValid;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "purge".to_string();
        let history = crate::transaction_history::TransactionHistory::empty();

        assert!(rule
            .check_transaction(&tx, &history, &config_with_methods(rule.id(), TEST_METHODS))
            .is_none());

        let v = rule
            .check_transaction(
                &tx,
                &history,
                &config_with_methods(rule.id(), &["GET", "PURGE"]),
            )
            .expect("a name in the array is the whole reason this spelling is reported");
        assert!(v.message.contains("'purge'") && v.message.contains("'PURGE'"));
    }

    /// `token` is `1*tchar`, and a character scan has nothing to object to in the
    /// empty string -- so the floor is a question of its own. No rule in the
    /// catalogue answered it before this one.
    #[test]
    fn an_empty_method_token_is_reported() {
        let v = check("").expect("`method = token` has a one-character floor");
        assert!(v.message.contains("empty method token"));
    }

    /// A DEL interpolated raw names nothing: the finding said "contains ''".
    #[test]
    fn an_unprintable_character_is_named_rather_than_printed() {
        let v = check("GET\u{7f}").expect("DEL is not a tchar");
        assert!(
            v.message.contains("\\u{7f}"),
            "an octet that prints as nothing has to be named: {}",
            v.message
        );
    }

    /// The case question is asked only of a string that is a `token` to begin with,
    /// so a method failing both reads as the grammar defect it is.
    #[test]
    fn a_non_token_is_reported_as_one_rather_than_as_a_spelling() {
        let v = check("ge@t").expect("'@' is not a tchar");
        assert!(v.message.contains("`tchar`"), "{}", v.message);
    }

    /// Nothing is read from the configuration until a request is about to be
    /// reported: a conforming method draws nothing even from a configuration that
    /// would fail to parse.
    #[test]
    fn a_conforming_method_never_reaches_the_configuration() {
        let rule = ClientRequestMethodTokenValid;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.method = "GET".to_string();
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        assert!(parse_method_token_config(&cfg, rule.id()).is_err());
        assert!(rule
            .check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg
            )
            .is_none());
    }

    #[rstest]
    #[case(toml::Value::Array(vec![]), "cannot be empty")]
    #[case(toml::Value::String("GET".into()), "must be an array")]
    #[case(
        toml::Value::Array(vec![toml::Value::Integer(1)]),
        "at index 0 must be a string"
    )]
    fn the_array_is_validated(#[case] value: toml::Value, #[case] expected: &str) {
        let rule = ClientRequestMethodTokenValid;
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        table.insert("severity".to_string(), toml::Value::String("warn".into()));
        table.insert("registered_methods".to_string(), value);
        cfg.rules
            .insert(rule.id().to_string(), toml::Value::Table(table));

        let err = parse_method_token_config(&cfg, rule.id())
            .expect_err("the array is required and typed");
        assert!(err.to_string().contains(expected), "{}", err);
    }

    #[test]
    fn scope_is_client() {
        let rule = ClientRequestMethodTokenValid;
        assert_eq!(rule.scope(), crate::rules::RuleScope::Client);
    }

    /// The shipped array is what a deployment starts from, so it has to parse and to
    /// hold the names the rule's own examples turn on.
    #[test]
    fn config_example_ships_the_array() {
        let rule = ClientRequestMethodTokenValid;
        let toml_src = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../config_example.toml"),
        )
        .expect("config_example.toml must be readable");
        let parsed: toml::Value =
            toml::from_str(&toml_src).expect("config_example.toml must parse");
        let arr = parsed
            .get("rules")
            .and_then(|r| r.get(rule.id()))
            .and_then(|r| r.get("registered_methods"))
            .and_then(|v| v.as_array())
            .expect("rule must ship a registered_methods array in config_example.toml");
        let names: Vec<&str> = arr.iter().filter_map(|v| v.as_str()).collect();
        for expected in ["GET", "POST", "PATCH", "PROPFIND"] {
            assert!(
                names.contains(&expected),
                "{expected} missing from the array"
            );
        }
    }
}
