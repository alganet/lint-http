// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::helpers::structured_fields::*;
use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessagePermissionsPolicyDirectivesValid;

impl Rule for MessagePermissionsPolicyDirectivesValid {
    fn id(&self) -> &'static str {
        "message_permissions_policy_directives_valid"
    }

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
        // Only inspect responses (server header)
        let resp = tx.response.as_ref()?;

        // Every field line, joined first. The rule used to validate each line on
        // its own, and a Dictionary is not a per-line structure: § 4.2 makes
        // combining a MUST and says why, and § 3.2 notes that members may be
        // spread across lines deliberately. Judging a line alone described a
        // message nobody sends.
        // cite(RFC 9651 § 4.2): "When generating input_bytes, parsers MUST combine all field lines in the same section (header or trailer) that case-insensitively match the field name into one comma-separated field-value, as per Section 5.2 of [HTTP]; this assures that the entire field value is processed correctly."
        let mut lines: Vec<&str> = Vec::new();
        for hv in resp.headers.get_all("permissions-policy").iter() {
            // Not "valid UTF-8", which is what this used to say and is a
            // different claim: a well-formed multi-byte character fails here
            // too. Structured Fields are ASCII, and a byte outside it is a
            // parse failure at step 1, before any of this field's own grammar
            // is consulted -- so the whole field goes.
            // cite(RFC 9651 § 4.2): "Convert input_bytes into an ASCII string input_string; if conversion fails, fail parsing."
            let Ok(v) = hv.to_str() else {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Permissions-Policy contains a byte outside ASCII, so the field \
                              fails Structured Fields parsing and every directive in it is \
                              discarded"
                        .into(),
                });
            };
            lines.push(v);
        }
        if lines.is_empty() {
            return None;
        }
        let joined = lines.join(", ");
        let s = joined.trim();

        {
            // An empty value is *not* a parse failure -- § 4.2.2 ends by
            // returning an empty Dictionary -- so nothing is discarded and the
            // message no longer implies otherwise. It is still worth saying:
            // § 3.2 is explicit that an empty Dictionary is spelled by leaving
            // the field out, so a server sending this one wrote a header that
            // does nothing.
            // cite(RFC 9651 § 4.2.2): "No structured data has been found; return dictionary (which is empty)."
            // cite(RFC 9651 § 3.2): "As with Lists, an empty Dictionary is represented by omitting the entire field."
            if s.is_empty() {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: "Permissions-Policy is empty, which grants and denies nothing; an \
                              empty policy is written by omitting the field"
                        .into(),
                });
            }

            // Neither specification says "invalid" about any of this, and the
            // wrapper used to. Both define *ignore* semantics, at two different
            // scopes, and which one applies is the thing a reader needs:
            //
            //  - A Structured Fields parse failure -- a member name with an
            //    uppercase letter, an unterminated inner list, a control
            //    character -- takes the whole field with it. RFC 9651 is
            //    deliberately absolute about this, and forbids field
            //    specifications from softening it, so the cost of one stray
            //    capital is every directive in the header.
            //    cite(RFC 9651 § 4.2): "If parsing fails, either the entire field value MUST be ignored (i.e., treated as if the field were not present in the section), or alternatively the complete HTTP message MUST be treated as malformed."
            //
            //  - A value that parses but is not an allowlist costs one
            //    directive; the rest of the policy is still enforced.
            //    cite(Permissions Policy § 5.2): "Member Values of any other form will cause the entire Dictionary Member to be ignored by the processing steps."
            //
            // Either way the finding is that something the server wrote will
            // not be enforced, which is what the message says now.
            // cite(Permissions Policy): "The `Permissions-Policy` HTTP header field can be used in the response (server to client) to communicate the permissions policy that should be enforced by the client."
            if let Some(msg) = validate_permissions_policy(s) {
                return Some(Violation {
                    rule: self.id().into(),
                    severity: config.severity,
                    message: format!(
                        "Permissions-Policy will not be enforced as written: {}",
                        msg
                    ),
                });
            }
        }

        None
    }

    fn description(&self) -> &'static str {
        "Reports a `Permissions-Policy` response header carrying something a browser will not enforce. Neither specification calls any of this \"invalid\" — both define **ignore** semantics — so the finding is always that the server wrote a policy that will not take effect, at one of two scopes.\n\n**The whole field, or one directive.** A Structured Fields parse failure discards everything: RFC 9651 §4.2, \"If parsing fails, either the entire field value MUST be ignored … or alternatively the complete HTTP message MUST be treated as malformed\", and field specifications are explicitly not allowed to loosen that. So one uppercase letter in a member name costs every directive in the header. A value that parses but is not an allowlist costs only its own directive — §5.2, \"Member Values of any other form will cause the entire Dictionary Member to be ignored\". The messages say which.\n\n**Member names are SF keys, not §5.1 feature-identifiers.** The Permissions Policy spec serializes a policy directive twice: §5.1 for the HTML `allow` attribute, where `feature-identifier = 1*( ALPHA / DIGIT / \"-\" )`, and §5.2 for this header, where the value is an `sf-dictionary`. This rule reads the header, so a member name is an SF key: lowercase only, beginning with a letter or `*`, and permitting `_`, `.` and `*`. It used to apply §5.1's production here, which accepted `Geolocation=(self)` and rejected `a_b=(self)`.\n\n**Allowlist values are a closed list.** §5.2 permits a String, the Token `*`, the Token `self`, or an Inner List of those — nothing else. Tokens keep their case, so `SELF` is not `self`. Items *inside* an inner list are deliberately not policed: §5.2 says unknown ones are ignored and the member is processed without them, which costs one origin rather than the directive.\n\n**Field lines are joined before parsing**, as RFC 9651 §4.2 requires — a Dictionary may have its members spread across lines, so judging a line on its own describes a message nobody sent. A member repeated across the joined value loses all but its last allowlist (§4.2.2), which is not an error and not visible in the header, so it is reported.\n\n**Unknown feature names are not reported.** §5.2 says a member naming no supported feature is ignored, and RFC 9651 §3.2 says recipients MUST ignore members with unknown keys — so a name this rule does not recognise is not a defect, and there is no allowlist of features here."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "Permissions Policy",
                section: None,
                url: "https://w3c.github.io/webappsec-permissions-policy/#structured-header-serialization",
                note: "§5.2 Structured header serialization — the production this rule enforces. Not §5.1, which is the HTML attribute and has a different feature-identifier grammar. No section number: an editor's draft renumbers",
            },
            crate::rules::SpecRef {
                spec: "RFC 9651",
                section: Some("3.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9651.html#section-3.2",
                note: "Dictionaries — member keys cannot contain uppercase, unknown members MUST be ignored, and members may be split across field lines",
            },
            crate::rules::SpecRef {
                spec: "RFC 9651",
                section: Some("4.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9651.html#section-4.2",
                note: "Parsing — a failure discards the entire field value, which is why a malformed member name is not a local problem",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "HTTP/1.1 200 OK\nPermissions-Policy: geolocation=(self \"https://example.com\"), fullscreen=(), payment=(\"https://pay.example\");report-to=\"endpoint\"\n",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(underscores and dots are ordinary SF key characters)"),
                snippet: "HTTP/1.1 200 OK\nPermissions-Policy: ch-ua_full.version=*\n",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(uppercase in a member name discards the whole field)"),
                snippet: "HTTP/1.1 200 OK\nPermissions-Policy: Geolocation=(self), camera=()\n",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(a bare token is not an allowlist)"),
                snippet: "HTTP/1.1 200 OK\nPermissions-Policy: geolocation=SELF\n",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(a bare member name has no allowlist at all)"),
                snippet: "HTTP/1.1 200 OK\nPermissions-Policy: geolocation\n",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(report-to must be a String)"),
                snippet: "HTTP/1.1 200 OK\nPermissions-Policy: geolocation=(self);report-to=endpoint\n",
            },
        ]
    }
}

// Minimal validator focused on semantics required by the Permissions Policy spec:
// - top-level value must be a dictionary (comma-separated members)
// - each member must be FeatureIdentifier = MemberValue
// - member name: an SF key (§ 5.2), not § 5.1's HTML-attribute feature-identifier
// - MemberValue: token '*', token 'self', string, or inner-list '(...)'
// - MemberValue may have parameters after it; only parameter name 'report-to' is validated to be a quoted-string
// Conservative: relies on liberal parsing of inner-list contents; primary goal is to catch common mistakes
fn validate_permissions_policy(s: &str) -> Option<String> {
    // Reject control characters
    if s.bytes().any(|b| (b < 0x20 && b != b'\t') || b == 0x7f) {
        return Some(
            "contains control characters, so the field fails Structured Fields parsing and \
             every directive in it is discarded"
                .into(),
        );
    }

    let mut seen_keys = std::collections::HashSet::new();
    let members = split_commas_outside_quotes(s);
    for m in members {
        let m = m.trim();
        if m.is_empty() {
            return Some("empty directive/member".into());
        }

        // find '=' outside quotes
        let eq = find_char_outside_quotes(m, '=');
        if eq.is_none() {
            return Some(format!("member '{}' missing '=' and value", m));
        }
        let eq = eq.unwrap();
        let (left, right) = m.split_at(eq);
        let mut feature_part = left.trim();
        let value_part = right[1..].trim(); // drop '='

        // feature_part may contain params (e.g., key;param=1). Keep only the key name
        if let Some(semipos) = find_char_outside_quotes(feature_part, ';') {
            feature_part = feature_part[..semipos].trim();
        }

        if !is_valid_feature_identifier(feature_part) {
            return Some(format!(
                "invalid feature identifier '{}': a Dictionary member name is an SF key \
                 (lowercase, starting with a letter or '*'), and a key that is not one fails \
                 parsing -- which discards every directive in the field, not just this one",
                feature_part
            ));
        }

        // A repeated key is not a parse failure and not an error: the parser
        // keeps the last one and the earlier directive simply stops existing.
        // That is precisely this rule's subject -- something the server wrote
        // that will not be enforced -- and it is invisible without being told,
        // since the header still looks like it says both things. Keys are
        // compared character for character, which § 4.2.2 says outright and
        // which the key grammar makes moot anyway.
        // cite(RFC 9651 § 4.2.2): "Note that when duplicate Dictionary keys are encountered, all but the last instance are ignored."
        if !seen_keys.insert(feature_part.to_string()) {
            return Some(format!(
                "feature '{}' is given more than once; all but the last are ignored, so the \
                 earlier allowlist has no effect",
                feature_part
            ));
        }

        // value_part may contain parameters separated by ';' outside quotes
        let parts = split_semicolons_outside_quotes(value_part);
        let item = parts.first().map(|s| s.trim()).unwrap_or("");
        if item.is_empty() {
            return Some(format!("member '{}' has empty value", feature_part));
        }

        // Disallow bare booleans, numbers, and byte-sequences as member values
        if item.starts_with('?') {
            return Some(format!(
                "member '{}' has boolean value not allowed",
                feature_part
            ));
        }
        if is_number(item) {
            return Some(format!(
                "member '{}' has numeric value not allowed",
                feature_part
            ));
        }
        if is_byte_sequence(item) {
            return Some(format!(
                "member '{}' has byte-sequence value not allowed",
                feature_part
            ));
        }

        // Allowed item forms: inner list '(...)', quoted-string '"..."', token '*' or 'self', or token-like
        if item.starts_with('(') {
            if !item.ends_with(')') {
                return Some(format!(
                    "member '{}' has unterminated inner-list",
                    feature_part
                ));
            }
            // inner-list contents are permissively accepted; ensure there are no empty members like '(,)'
            let inner = &item[1..item.len() - 1];
            if inner.trim() == "" {
                // empty inner list is acceptable: ()
            } else {
                // ensure no empty inner members after space-splitting outside quotes
                let members = split_spaces_outside_quotes(inner);
                for im in members {
                    if im.trim().is_empty() {
                        return Some(format!(
                            "member '{}' has empty inner-list member",
                            feature_part
                        ));
                    }
                }
            }
        } else if item.starts_with('"') {
            if !is_quoted_string(item) {
                return Some(format!(
                    "member '{}' has invalid quoted-string",
                    feature_part
                ));
            }
        } else if item == "*" || item == "self" {
            // § 5.2 names two permitted Tokens, and a Token keeps its case:
            // RFC 9651 § 4.2.6 consumes each character and appends it to the
            // output unchanged, and nothing anywhere folds a Token. Compare
            // § 3.2, which says outright that member *keys* cannot contain
            // uppercase -- the specification distinguishes the two cases, so
            // this code should not have folded them together.
            //
            // `SELF` is therefore a different Token from `self`, which makes it
            // a Member Value of "any other form", and § 5.2 says what becomes
            // of those: the directive is dropped. `eq_ignore_ascii_case` here
            // called that conforming.
            // cite(Permissions Policy § 5.2): "The Member Values represent allowlists, and must be one of:"
            // cite(Permissions Policy § 5.2): "Member Values of any other form will cause the entire Dictionary Member to be ignored by the processing steps."
            // cite(RFC 9651 § 3.2): "Member keys cannot contain uppercase characters."
        } else {
            // Everything else. § 5.2's list of permitted Member Values is
            // closed -- a String, the Token `*`, the Token `self`, or an Inner
            // List of those -- so a bare Token that is neither `*` nor `self`
            // is not a narrower kind of allowlist, it is not an allowlist at
            // all. This branch used to accept any syntactically well-formed
            // token, which let `geolocation=camera` and `geolocation=SELF`
            // through as conforming when a browser drops both.
            //
            // Note the asymmetry with Inner List contents just above, which
            // stay permissive on purpose: § 5.2 says unknown items *inside* a
            // list are ignored and the Member Value is processed without them,
            // so an odd entry there costs one origin. An odd value out here
            // costs the whole directive.
            // cite(Permissions Policy § 5.2): "Any other items inside of an Inner List will be ignored by the processing steps, and the Member Value will be processed as if they were not present."
            let shape = if is_valid_token_like(item) {
                "token"
            } else {
                "value"
            };
            return Some(format!(
                "member '{}' has {} '{}', which is not an allowlist: § 5.2 permits a string, \
                 the token '*', the token 'self', or an inner list of those",
                feature_part, shape, item
            ));
        }

        // Validate parameters (if any): only 'report-to' is checked to be a quoted-string when present.
        for p in parts.iter().skip(1) {
            let p = p.trim();
            if p.is_empty() {
                return Some(format!("empty parameter for feature '{}'", feature_part));
            }
            if let Some(eqpos) = find_char_outside_quotes(p, '=') {
                let (pn, pv) = p.split_at(eqpos);
                let pn = pn.trim();
                let pv = pv[1..].trim();
                if pn.eq_ignore_ascii_case("report-to") {
                    if !is_quoted_string(pv) {
                        return Some(format!(
                            "parameter 'report-to' for '{}' must be a quoted-string",
                            feature_part
                        ));
                    }
                } else {
                    // other parameters are allowed but must at least be valid token or quoted-string
                    if !(is_valid_sf_key(pn)
                        && (is_valid_token_like(pv) || is_quoted_string(pv) || is_number(pv)))
                    {
                        return Some(format!(
                            "invalid parameter '{}' for feature '{}'",
                            pn, feature_part
                        ));
                    }
                }
            } else {
                // bare parameter name
                if !is_valid_sf_key(p) {
                    return Some(format!(
                        "invalid bare parameter '{}' for '{}'",
                        p, feature_part
                    ));
                }
            }
        }
    }
    None
}

// Shared parsing helpers (splitting, quoted-string, byte-seq, key/token-like)
// have been moved to `crate::helpers::structured_fields` and are imported at
// the top of this file. The feature-specific helpers remain here.

/// Whether a Dictionary member name is one this field can carry.
///
/// This used to be `1*( ALPHA / DIGIT / "-" )`, transcribed from the Permissions
/// Policy spec's **§ 5.1**, which is the *HTML attribute* serialization. The
/// header is § 5.2, where a directive is a Structured Fields Dictionary and a
/// member name is an SF key -- a different production with different characters
/// on both sides of the difference.
///
/// `ALPHA` includes uppercase, so the old check accepted `Geolocation=(self)`.
/// An SF key cannot contain uppercase, and the consequence is not a shrug: the
/// Dictionary fails to parse, and a failed parse discards **the entire field**,
/// so every other directive beside it stops being enforced. It also rejected
/// `_`, `.` and `*`, which are ordinary SF key characters, and accepted a
/// leading digit, which an SF key may not start with.
///
/// The rule already knew all of this -- it validates *parameter* names with
/// `is_valid_sf_key`, and has tests pinning that uppercase is rejected there and
/// that `.`/`_`/`*` are accepted. Member names simply never got the same
/// treatment.
// cite(Permissions Policy § 5.2): "The Member Names must be Tokens."
// cite(RFC 9651 § 3.2): "Member keys cannot contain uppercase characters."
fn is_valid_feature_identifier(s: &str) -> bool {
    is_valid_sf_key(s)
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &MessagePermissionsPolicyDirectivesValid;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// Every published snippet is run through the rule. The old set carried
    /// `#` comments inside the header value -- no HTTP message has one, and
    /// they were part of the value being validated, so two of them were
    /// non-compliant partly because of the annotation explaining why.
    #[test]
    fn published_examples_are_judged_the_way_they_are_labelled() {
        use crate::rules::{Compliance, Rule as _};
        let rule = MessagePermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);

        for ex in rule.examples() {
            let pairs: Vec<(&str, &str)> = ex
                .snippet
                .lines()
                .skip(1)
                .filter(|l| !l.trim().is_empty())
                .map(|l| {
                    let (k, v) = l
                        .split_once(": ")
                        .unwrap_or_else(|| panic!("not a header line: {l:?}"));
                    (k, v)
                })
                .collect();
            assert!(
                !ex.snippet.contains('#'),
                "example carries a comment no HTTP message has: {:?}",
                ex.snippet
            );

            let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
            tx.response.as_mut().unwrap().headers =
                crate::test_helpers::make_headers_from_pairs(&pairs);

            let found = rule.check_transaction(
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg,
            );
            match ex.compliance {
                Compliance::Compliant => assert!(
                    found.is_none(),
                    "rule rejects its Compliant example {:?}: {found:?}",
                    ex.snippet
                ),
                Compliance::NonCompliant => {
                    let found = found.unwrap_or_else(|| {
                        panic!("rule accepts its NonCompliant example {:?}", ex.snippet)
                    });
                    assert!(
                        found.message.contains("will not be enforced as written"),
                        "{found:?}"
                    );
                }
            }
        }
    }

    #[rstest]
    #[case(Some("geolocation=(self \"https://example.com\")"), false)]
    #[case(Some("fullscreen=()"), false)]
    #[case(
        Some("payment=(\"https://pay.example\") ; report-to=\"endpoint\""),
        false
    )]
    #[case(Some("feature=*"), false)]
    #[case(Some("feature=self"), false)]
    // A Token keeps its case, so these are not the Tokens § 5.2 names; each is
    // a Member Value "of any other form", and the directive is dropped.
    #[case(Some("feature=SELF"), true)]
    #[case(Some("feature=Self"), true)]
    #[case(Some("feature=(SELF)"), false)]
    // `_` is an ordinary SF key character. This asserted a violation, which
    // was § 5.1's HTML-attribute grammar speaking.
    #[case(Some("bad_feature_name=(self)"), false)]
    #[case(Some("a.b=(self)"), false)]
    #[case(Some("*=(self)"), false)]
    // Uppercase cannot appear in an SF key, and the Dictionary fails to parse.
    #[case(Some("Geolocation=(self)"), true)]
    #[case(Some("geoLocation=(self)"), true)]
    #[case(Some("geolocation"), true)]
    #[case(Some("geolocation=(self);report-to=endpoint"), true)]
    #[case(Some("geolocation=?1"), true)]
    #[case(Some(":byte:="), true)]
    #[case(None, false)]
    fn check_permissions_policy_cases(
        #[case] hdr: Option<&str>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = MessagePermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_permissions_policy_directives_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        if let Some(v) = hdr {
            tx.response.as_mut().unwrap().headers =
                crate::test_helpers::make_headers_from_pairs(&[("permissions-policy", v)]);
        }

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(v.is_some(), "expected violation for {:?}: got none", hdr);
        } else {
            assert!(
                v.is_none(),
                "did not expect violation for {:?}: got {:?}",
                hdr,
                v
            );
        }
        Ok(())
    }

    #[test]
    fn non_utf8_is_violation() -> anyhow::Result<()> {
        let rule = MessagePermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_permissions_policy_directives_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = hyper::HeaderMap::new();
        hm.insert(
            "permissions-policy",
            hyper::header::HeaderValue::from_bytes(&[0xff])?,
        );
        tx.response.as_mut().unwrap().headers = hm;

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn message_and_id() {
        let rule = MessagePermissionsPolicyDirectivesValid;
        assert_eq!(rule.id(), "message_permissions_policy_directives_valid");
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "message_permissions_policy_directives_valid");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn control_characters_are_rejected() {
        // hyper rejects control characters in header values; test validator directly instead
        let res = validate_permissions_policy("geo=\u{0001}");
        assert!(res.is_some());
        assert!(res.unwrap().contains("control characters"));
    }

    #[test]
    fn empty_directive_is_reported() {
        let rule = MessagePermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_permissions_policy_directives_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "permissions-policy",
            ",geolocation=(self)",
        )]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("empty directive"));
    }

    #[test]
    fn empty_value_is_reported() {
        let rule = MessagePermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_permissions_policy_directives_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("permissions-policy", "geolocation=")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("has empty value"));
    }

    #[test]
    fn numeric_values_are_rejected() {
        let rule = MessagePermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_permissions_policy_directives_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "permissions-policy",
            "geolocation=1",
        )]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("numeric value"));
    }

    #[test]
    fn unterminated_inner_list_is_rejected() {
        let rule = MessagePermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_permissions_policy_directives_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "permissions-policy",
            "geolocation=(self",
        )]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("unterminated inner-list"));
    }

    #[test]
    fn empty_inner_list_member_is_rejected() {
        let rule = MessagePermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_permissions_policy_directives_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "permissions-policy",
            "geolocation=(self  )",
        )]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("empty inner-list"));
    }

    #[test]
    fn invalid_quoted_string_is_rejected() {
        let rule = MessagePermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_permissions_policy_directives_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "permissions-policy",
            "geolocation=\"abc",
        )]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("invalid quoted-string"));
    }

    #[test]
    fn invalid_token_like_is_rejected() {
        let rule = MessagePermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_permissions_policy_directives_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "permissions-policy",
            "geolocation=1abc",
        )]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("is not an allowlist"));
    }

    #[test]
    fn empty_parameter_is_rejected() {
        let rule = MessagePermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_permissions_policy_directives_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "permissions-policy",
            "geolocation=(self);",
        )]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("empty parameter"));
    }

    #[test]
    fn invalid_bare_parameter_is_rejected() {
        let rule = MessagePermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_permissions_policy_directives_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "permissions-policy",
            "geolocation=(self);123",
        )]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("invalid bare parameter"));
    }

    #[test]
    fn invalid_parameter_value_is_rejected() {
        let rule = MessagePermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_permissions_policy_directives_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "permissions-policy",
            "geolocation=(self);foo=!",
        )]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("invalid parameter 'foo'"));
    }

    #[test]
    fn report_to_quoted_is_ok() {
        let rule = MessagePermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_permissions_policy_directives_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "permissions-policy",
            "geolocation=(self);report-to=\"endpoint\"",
        )]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn feature_part_params_ignored() {
        // a semicolon before the '=' with its own '=' makes the member malformed and should be rejected
        let rule = MessagePermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_permissions_policy_directives_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "permissions-policy",
            "geolocation;meta=1=(self)",
        )]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn decimal_number_value_is_rejected() {
        let rule = MessagePermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_permissions_policy_directives_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "permissions-policy",
            "geolocation=1.2",
        )]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("numeric value"));
    }

    #[test]
    fn byte_sequence_is_rejected() {
        let rule = MessagePermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_permissions_policy_directives_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "permissions-policy",
            "geolocation=:YWJj:",
        )]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("byte-sequence"));
    }

    #[test]
    fn param_with_number_value_is_ok() {
        let rule = MessagePermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_permissions_policy_directives_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "permissions-policy",
            "geolocation=(self);foo=1",
        )]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn bare_param_is_ok() {
        let rule = MessagePermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_permissions_policy_directives_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "permissions-policy",
            "geolocation=(self);foo",
        )]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn param_with_quoted_value_is_ok() {
        let rule = MessagePermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_permissions_policy_directives_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "permissions-policy",
            "geolocation=(self);foo=\"bar\"",
        )]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn a_bare_token_that_is_not_star_or_self_is_not_an_allowlist() {
        let rule = MessagePermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_permissions_policy_directives_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "permissions-policy",
            "geolocation=feat:sub/1.2-_",
        )]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        // A well-formed Token, and § 5.2's list of Member Values does not
        // include one. A browser drops the directive; this asserted it was fine.
        assert!(v.is_some_and(|v| v.message.contains("is not an allowlist")));
    }

    #[test]
    fn star_param_name_is_ok() {
        let rule = MessagePermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_permissions_policy_directives_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "permissions-policy",
            "geolocation=(self);*=1",
        )]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn invalid_param_name_uppercase_is_rejected() {
        let rule = MessagePermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_permissions_policy_directives_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "permissions-policy",
            "geolocation=(self);Foo=1",
        )]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("invalid parameter 'Foo'"));
    }

    /// An SF key must begin with lowercase alpha or `*`, so a leading digit is
    /// not a valid member name. This asserted the opposite -- `ALPHA / DIGIT`
    /// is § 5.1's HTML-attribute production, not the header's.
    #[test]
    fn feature_starting_with_digit_is_rejected() {
        let rule = MessagePermissionsPolicyDirectivesValid;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "permissions-policy",
            "1feature=(self)",
        )]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
    }

    #[test]
    fn empty_header_value_is_violation() {
        let rule = MessagePermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_permissions_policy_directives_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("permissions-policy", "")]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("Permissions-Policy is empty"));
    }

    /// A repeated key is not an error and not a parse failure -- the parser
    /// keeps the last and the earlier directive stops existing. Invisible
    /// without being told, since the header still reads as saying both.
    #[rstest]
    #[case("geolocation=*, geolocation=()")]
    #[case("camera=(), geolocation=*, camera=(self)")]
    fn a_repeated_feature_loses_its_earlier_allowlist(#[case] value: &str) {
        let rule = MessagePermissionsPolicyDirectivesValid;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("permissions-policy", value)]);
        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(
            v.is_some_and(|v| v.message.contains("is given more than once")),
            "{value:?}"
        );
    }

    /// Field lines are joined before parsing, as § 4.2 requires, so a Dictionary
    /// spread across lines is one Dictionary -- including for the duplicate
    /// check, which per-line validation could never have seen.
    #[test]
    fn field_lines_are_joined_before_parsing() {
        use hyper::header::HeaderValue;
        let rule = MessagePermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);

        let mut ok = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = hyper::HeaderMap::new();
        hm.append(
            "permissions-policy",
            HeaderValue::from_static("geolocation=*"),
        );
        hm.append("permissions-policy", HeaderValue::from_static("camera=()"));
        ok.response.as_mut().unwrap().headers = hm;
        assert!(rule
            .check_transaction(
                &ok,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg
            )
            .is_none());

        let mut dup = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = hyper::HeaderMap::new();
        hm.append(
            "permissions-policy",
            HeaderValue::from_static("geolocation=*"),
        );
        hm.append(
            "permissions-policy",
            HeaderValue::from_static("geolocation=()"),
        );
        dup.response.as_mut().unwrap().headers = hm;
        let v = rule.check_transaction(
            &dup,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(
            v.is_some_and(|v| v.message.contains("is given more than once")),
            "a member repeated across lines is still a repeat"
        );
    }

    #[test]
    fn param_name_with_dot_underscore_star_is_ok() {
        let rule = MessagePermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "message_permissions_policy_directives_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "permissions-policy",
            "geolocation=(self);a.b_c*=1",
        )]);

        let v = rule.check_transaction(
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn quoted_string_with_control_char_is_rejected() {
        // hyper rejects control characters in header values; test validator directly instead
        let res = validate_permissions_policy("geolocation=\"a\u{0001}\"");
        assert!(res.is_some());
        // top-level control character check runs first
        assert!(res.unwrap().contains("control characters"));
    }
}
