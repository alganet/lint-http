// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::helpers::structured_fields::*;
use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};

pub struct PermissionsPolicyDirectivesValid;

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const PERMISSIONS_POLICY: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "Permissions Policy",
    section: None,
    url: "https://w3c.github.io/webappsec-permissions-policy/#structured-header-serialization",
    note: "§5.2 Structured header serialization — the production this rule enforces. Not §5.1, which is the HTML attribute and has a different feature-identifier grammar. No section number: an editor's draft renumbers",
};
const RFC_9651_3_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9651",
    section: Some("3.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9651.html#section-3.2",
    note: "Dictionaries — member keys cannot contain uppercase, unknown members MUST be ignored, and members may be split across field lines",
};
const RFC_9651_4_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9651",
    section: Some("4.2"),
    url: "https://www.rfc-editor.org/rfc/rfc9651.html#section-4.2",
    note: "Parsing — a failure discards the entire field value, which is why a malformed member name is not a local problem",
};

impl RuleMeta for PermissionsPolicyDirectivesValid {
    fn id(&self) -> &'static str {
        "permissions_policy_directives_valid"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
severity = "warn"
"#
    }

    fn description(&self) -> &'static str {
        "Reports a `Permissions-Policy` response header carrying something a browser will not enforce. Neither specification calls any of this \"invalid\" — both define **ignore** semantics — so the finding is always that the server wrote a policy that will not take effect, at one of two scopes.\n\n**The whole field, or one directive.** A Structured Fields parse failure discards everything: RFC 9651 §4.2, \"If parsing fails, either the entire field value MUST be ignored … or alternatively the complete HTTP message MUST be treated as malformed\", and field specifications are explicitly not allowed to loosen that. So one uppercase letter in a member name costs every directive in the header. A value that parses but is not an allowlist costs only its own directive — §5.2, \"Member Values of any other form will cause the entire Dictionary Member to be ignored\". The messages say which, and so does their number: a parse failure is reported alone because nothing else in the field survived it, while every directive that parsed and will be ignored is reported beside the others like it. A member with no `=` at all belongs to the second group — §4.2.2 reads a bare key as the Boolean true, which parses, so the cost is that one directive.\n\n**Member names are SF keys, not §5.1 feature-identifiers.** The Permissions Policy spec serializes a policy directive twice: §5.1 for the HTML `allow` attribute, where `feature-identifier = 1*( ALPHA / DIGIT / \"-\" )`, and §5.2 for this header, where the value is an `sf-dictionary`. This rule reads the header, so a member name is an SF key: lowercase only, beginning with a letter or `*`, and permitting `_`, `.` and `*`. It used to apply §5.1's production here, which accepted `Geolocation=(self)` and rejected `a_b=(self)`.\n\n**Allowlist values are a closed list.** §5.2 permits a String, the Token `*`, the Token `self`, or an Inner List of those — nothing else. Tokens keep their case, so `SELF` is not `self`. Items *inside* an inner list are deliberately not policed: §5.2 says unknown ones are ignored and the member is processed without them, which costs one origin rather than the directive.\n\n**Field lines are joined before parsing**, as RFC 9651 §4.2 requires — a Dictionary may have its members spread across lines, so judging a line on its own describes a message nobody sent. A member repeated across the joined value loses all but its last allowlist (§4.2.2), which is not an error and not visible in the header, so it is reported.\n\n**Unknown feature names are not reported.** §5.2 says a member naming no supported feature is ignored, and RFC 9651 §3.2 says recipients MUST ignore members with unknown keys — so a name this rule does not recognise is not a defect, and there is no allowlist of features here."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[PERMISSIONS_POLICY, RFC_9651_3_2, RFC_9651_4_2]
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

impl Rule for PermissionsPolicyDirectivesValid {
    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
    }

    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        // Only inspect responses (server header)
        let Some(resp) = tx.response.as_ref() else {
            return Vec::new();
        };

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
                return vec![self.cited(
                    &RFC_9651_4_2,
                    ctx.severity,
                    "Permissions-Policy contains a byte outside ASCII, so the field \
                                  fails Structured Fields parsing and every directive in it is \
                                  discarded"
                        .into(),
                )];
            };
            lines.push(v);
        }
        if lines.is_empty() {
            return Vec::new();
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
                return vec![self.violation(
                    ctx.severity,
                    "Permissions-Policy is empty, which grants and denies nothing; an \
                                  empty policy is written by omitting the field"
                        .into(),
                )];
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
            // cite(Permissions Policy § 6.1): "The `Permissions-Policy` HTTP header field can be used in the response (server to client) to communicate the permissions policy that should be enforced by the client."
            // One finding per message the validator has, each with the same
            // preamble: a parse failure comes back alone because it took the
            // whole field with it, and a directive that parsed and will be
            // ignored comes back beside the others like it.
            validate_permissions_policy(s)
                .into_iter()
                .map(|msg| {
                    self.violation(
                        ctx.severity,
                        format!(
                            "Permissions-Policy will not be enforced as written: {}",
                            msg
                        ),
                    )
                })
                .collect()
        }
    }
}

// Minimal validator focused on semantics required by the Permissions Policy spec:
// - top-level value must be a dictionary (comma-separated members)
// - each member must be FeatureIdentifier = MemberValue
// - member name: an SF key (§ 5.2), not § 5.1's HTML-attribute feature-identifier
// - MemberValue: token '*', token 'self', string, or inner-list '(...)'
// - MemberValue may have parameters after it; only parameter name 'report-to' is validated to be a quoted-string
// Conservative: relies on liberal parsing of inner-list contents; primary goal is to catch common mistakes
///
/// The two scopes § 5.2 and RFC 9651 § 4.2 define decide the shape of the
/// answer. A Structured Fields parse failure discards the whole field, so it is
/// one message and the only one -- there are no surviving directives to describe
/// and the scan stops. A member that parses and is then ignored costs one
/// directive, so those accumulate: a policy with two unenforceable directives is
/// two findings, and used to be one finding and a silence.
fn validate_permissions_policy(s: &str) -> Vec<String> {
    // Reject control characters
    if s.bytes().any(|b| (b < 0x20 && b != b'\t') || b == 0x7f) {
        return vec![
            "contains control characters, so the field fails Structured Fields parsing and \
             every directive in it is discarded"
                .into(),
        ];
    }

    let mut ignored: Vec<String> = Vec::new();
    let mut seen_keys = std::collections::HashSet::new();
    for member in split_commas_outside_quotes(s) {
        match judge_member(member.trim(), &mut seen_keys) {
            // The whole field is gone, so there are no surviving directives to
            // describe and no reason to keep reading.
            Verdict::FieldDiscarded(message) => return vec![message],
            Verdict::DirectiveIgnored(message) => ignored.push(message),
            Verdict::Enforced => {}
        }
    }
    ignored
}

/// What becomes of one Dictionary member.
///
/// The distinction is the whole subject of this rule, and it is the
/// specification's own: a Structured Fields *parse* failure discards the entire
/// field, so it is one message and the only one; a member that parses and is
/// then dropped for its form costs one directive, so those accumulate.
enum Verdict {
    /// The field fails to parse: every directive in it is discarded.
    FieldDiscarded(String),
    /// This directive parses and is then ignored by the processing steps.
    DirectiveIgnored(String),
    /// The directive is enforced as written.
    Enforced,
}

/// Judge one Dictionary member: its name, its allowlist, and its parameters.
fn judge_member(member: &str, seen_keys: &mut std::collections::HashSet<String>) -> Verdict {
    if member.is_empty() {
        return Verdict::FieldDiscarded("empty directive/member".into());
    }

    // A member with no `=` is not malformed and this used to say it was.
    // § 4.2.2 reads a bare key as the Boolean true, which parses -- so the
    // field survives and this one directive does not: a Boolean is a Member
    // Value of "any other form", and § 5.2 drops the member for it. The same
    // finding as the explicit `?1` below, reached by leaving the value out.
    // cite(RFC 9651 § 4.2.2): "Let value be Boolean true."
    let Some(eq) = find_char_outside_quotes(member, '=') else {
        return Verdict::DirectiveIgnored(format!(
            "member '{}' has no value, which is the Boolean true and not an allowlist: \
             § 5.2 permits a string, the token '*', the token 'self', or an inner list \
             of those",
            member
        ));
    };
    let (left, right) = member.split_at(eq);
    let value_part = right[1..].trim(); // drop '='

    // The name may carry parameters (`key;param=1`); only the key names the feature.
    let mut feature = left.trim();
    if let Some(semicolon) = find_char_outside_quotes(feature, ';') {
        feature = feature[..semicolon].trim();
    }

    if !is_valid_feature_identifier(feature) {
        return Verdict::FieldDiscarded(format!(
            "invalid feature identifier '{}': a Dictionary member name is an SF key \
             (lowercase, starting with a letter or '*'), and a key that is not one fails \
             parsing -- which discards every directive in the field, not just this one",
            feature
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
    if !seen_keys.insert(feature.to_string()) {
        return Verdict::DirectiveIgnored(format!(
            "feature '{}' is given more than once; all but the last are ignored, so the \
             earlier allowlist has no effect",
            feature
        ));
    }

    let parts = split_semicolons_outside_quotes(value_part);
    let item = parts.first().map(|s| s.trim()).unwrap_or("");
    // Nothing after the `=` fails § 4.2.2's parse of a Dictionary member
    // value, so this is the whole field rather than the one directive.
    if item.is_empty() {
        return Verdict::FieldDiscarded(format!("member '{}' has empty value", feature));
    }

    match judge_allowlist(item, feature) {
        Verdict::Enforced => judge_parameters(&parts, feature),
        verdict => verdict,
    }
}

/// Judge the Member Value: is it one of the forms § 5.2 permits?
// cite(Permissions Policy § 5.2): "The Member Values represent allowlists, and must be one of:"
// cite(Permissions Policy § 5.2): "Member Values of any other form will cause the entire Dictionary Member to be ignored by the processing steps."
fn judge_allowlist(item: &str, feature: &str) -> Verdict {
    // A Boolean, a Number and a Byte Sequence each parse and are then dropped
    // for their form, so each costs its own directive and the scan carries on.
    let dropped_for_its_form = if item.starts_with('?') {
        Some("boolean")
    } else if is_number(item) {
        Some("numeric")
    } else if is_byte_sequence(item) {
        Some("byte-sequence")
    } else {
        None
    };
    if let Some(form) = dropped_for_its_form {
        return Verdict::DirectiveIgnored(format!(
            "member '{}' has {} value not allowed",
            feature, form
        ));
    }

    if let Some(inner) = item.strip_prefix('(') {
        let Some(inner) = inner.strip_suffix(')') else {
            return Verdict::FieldDiscarded(format!(
                "member '{}' has unterminated inner-list",
                feature
            ));
        };
        // Inner-list contents are permissively accepted — see the asymmetry
        // noted below — but an empty member is a parse failure.
        if !inner.trim().is_empty()
            && split_spaces_outside_quotes(inner)
                .iter()
                .any(|m| m.trim().is_empty())
        {
            return Verdict::FieldDiscarded(format!(
                "member '{}' has empty inner-list member",
                feature
            ));
        }
        return Verdict::Enforced;
    }

    if item.starts_with('"') {
        return if is_quoted_string(item) {
            Verdict::Enforced
        } else {
            Verdict::FieldDiscarded(format!("member '{}' has invalid quoted-string", feature))
        };
    }

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
    // cite(RFC 9651 § 3.2): "Member keys cannot contain uppercase characters."
    if item == "*" || item == "self" {
        return Verdict::Enforced;
    }

    // Everything else. § 5.2's list of permitted Member Values is
    // closed -- a String, the Token `*`, the Token `self`, or an Inner
    // List of those -- so a bare Token that is neither `*` nor `self`
    // is not a narrower kind of allowlist, it is not an allowlist at
    // all. This branch used to accept any syntactically well-formed
    // token, which let `geolocation=camera` and `geolocation=SELF`
    // through as conforming when a browser drops both.
    //
    // Note the asymmetry with Inner List contents above, which stay
    // permissive on purpose: § 5.2 says unknown items *inside* a list are
    // ignored and the Member Value is processed without them, so an odd entry
    // there costs one origin. An odd value out here costs the whole directive.
    // cite(Permissions Policy § 5.2): "Any other items inside of an Inner List will be ignored by the processing steps, and the Member Value will be processed as if they were not present."
    let shape = if is_valid_token_like(item) {
        "token"
    } else {
        "value"
    };
    Verdict::DirectiveIgnored(format!(
        "member '{}' has {} '{}', which is not an allowlist: § 5.2 permits a string, \
         the token '*', the token 'self', or an inner list of those",
        feature, shape, item
    ))
}

/// Judge the parameters after the Member Value. Only `report-to` has a shape
/// this field's own definition constrains; the rest are judged as Structured
/// Fields and nothing more.
///
/// The scan runs to the end even once a `report-to` has been found wanting,
/// because a parse failure in a *later* parameter discards the whole field and
/// outranks it. A second bad `report-to` on the same directive adds nothing:
/// one directive that will not be enforced is one finding.
fn judge_parameters(parts: &[&str], feature: &str) -> Verdict {
    let mut ignored: Option<String> = None;
    for parameter in parts.iter().skip(1) {
        let parameter = parameter.trim();
        if parameter.is_empty() {
            return Verdict::FieldDiscarded(format!("empty parameter for feature '{}'", feature));
        }

        let Some(eq) = find_char_outside_quotes(parameter, '=') else {
            // A bare parameter name, which is the Boolean true — a value this
            // field says nothing about, so only the key grammar is asked.
            if !is_valid_sf_key(parameter) {
                return Verdict::FieldDiscarded(format!(
                    "invalid bare parameter '{}' for '{}'",
                    parameter, feature
                ));
            }
            continue;
        };
        let (name, value) = parameter.split_at(eq);
        let name = name.trim();
        let value = value[1..].trim();

        // Checked before the name is compared to anything, and for
        // every parameter rather than for all but one. A key cannot
        // hold an uppercase letter, so `Report-To` is not a differently
        // spelled `report-to`; it is a member the whole field dies on.
        // cite(RFC 9651 § 4.2.3.3): "If the first character of input_string is not lcalpha or "*", fail parsing."
        if !is_valid_sf_key(name) {
            return Verdict::FieldDiscarded(format!(
                "invalid parameter '{}' for feature '{}'",
                name, feature
            ));
        }

        if name == "report-to" {
            // The one per-directive failure among the parameters: the value
            // parses as a Structured Field and is refused by this field's own
            // definition, not by § 4.2.
            if !is_quoted_string(value) {
                ignored.get_or_insert_with(|| {
                    format!(
                        "parameter 'report-to' for '{}' must be a quoted-string",
                        feature
                    )
                });
            }
        } else if !is_bare_item(value) {
            // Any bare Item, not the three that used to be listed here.
            // A byte sequence, a Boolean, a Date and a Display String
            // are all parameter values, and § 5.2 says nothing about
            // parameters other than `report-to` -- so the only question
            // left at this site is the Structured Fields one.
            // cite(RFC 9651 § 4.2.3.2): "Let param_value be the result of running Parsing a Bare Item (Section 4.2.3.1) with input_string."
            return Verdict::FieldDiscarded(format!(
                "invalid parameter '{}' for feature '{}'",
                name, feature
            ));
        }
    }
    ignored.map_or(Verdict::Enforced, Verdict::DirectiveIgnored)
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
static REGISTRATION: &dyn crate::rules::Rule = &PermissionsPolicyDirectivesValid;

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
        use crate::rules::{Compliance, RuleMeta as _};
        let rule = PermissionsPolicyDirectivesValid;
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

            let found = crate::test_helpers::run_rule(
                &rule,
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
    // A bare key parses -- it is the Boolean true -- so the field survives and
    // this one directive does not.
    #[case(Some("geolocation"), true)]
    #[case(Some("geolocation=(self);report-to=endpoint"), true)]
    #[case(Some("geolocation=?1"), true)]
    #[case(Some(":byte:="), true)]
    #[case(None, false)]
    fn check_permissions_policy_cases(
        #[case] hdr: Option<&str>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = PermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "permissions_policy_directives_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        if let Some(v) = hdr {
            tx.response.as_mut().unwrap().headers =
                crate::test_helpers::make_headers_from_pairs(&[("permissions-policy", v)]);
        }

        let v = crate::test_helpers::run_rule(
            &rule,
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
        let rule = PermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "permissions_policy_directives_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = hyper::HeaderMap::new();
        hm.insert(
            "permissions-policy",
            hyper::header::HeaderValue::from_bytes(&[0xff])?,
        );
        tx.response.as_mut().unwrap().headers = hm;

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn message_and_id() {
        let rule = PermissionsPolicyDirectivesValid;
        assert_eq!(rule.id(), "permissions_policy_directives_valid");
        assert_eq!(rule.scope(), crate::rules::RuleScope::Server);
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "permissions_policy_directives_valid");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn control_characters_are_rejected() {
        // hyper rejects control characters in header values; test validator directly instead
        let res = validate_permissions_policy("geo=\u{0001}");
        assert_eq!(res.len(), 1, "{res:?}");
        assert!(res[0].contains("control characters"), "{}", res[0]);
    }

    #[test]
    fn empty_directive_is_reported() {
        let rule = PermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "permissions_policy_directives_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "permissions-policy",
            ",geolocation=(self)",
        )]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("empty directive"));
    }

    #[test]
    fn empty_value_is_reported() {
        let rule = PermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "permissions_policy_directives_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("permissions-policy", "geolocation=")]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("has empty value"));
    }

    #[test]
    fn numeric_values_are_rejected() {
        let rule = PermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "permissions_policy_directives_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "permissions-policy",
            "geolocation=1",
        )]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("numeric value"));
    }

    #[test]
    fn unterminated_inner_list_is_rejected() {
        let rule = PermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "permissions_policy_directives_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "permissions-policy",
            "geolocation=(self",
        )]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("unterminated inner-list"));
    }

    #[test]
    fn empty_inner_list_member_is_rejected() {
        let rule = PermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "permissions_policy_directives_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "permissions-policy",
            "geolocation=(self  )",
        )]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("empty inner-list"));
    }

    #[test]
    fn invalid_quoted_string_is_rejected() {
        let rule = PermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "permissions_policy_directives_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "permissions-policy",
            "geolocation=\"abc",
        )]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("invalid quoted-string"));
    }

    #[test]
    fn invalid_token_like_is_rejected() {
        let rule = PermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "permissions_policy_directives_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "permissions-policy",
            "geolocation=1abc",
        )]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("is not an allowlist"));
    }

    #[test]
    fn empty_parameter_is_rejected() {
        let rule = PermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "permissions_policy_directives_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "permissions-policy",
            "geolocation=(self);",
        )]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("empty parameter"));
    }

    #[test]
    fn invalid_bare_parameter_is_rejected() {
        let rule = PermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "permissions_policy_directives_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "permissions-policy",
            "geolocation=(self);123",
        )]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("invalid bare parameter"));
    }

    #[test]
    fn invalid_parameter_value_is_rejected() {
        let rule = PermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "permissions_policy_directives_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "permissions-policy",
            "geolocation=(self);foo=!",
        )]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("invalid parameter 'foo'"));
    }

    #[rstest]
    #[case("geolocation=(self);h=:YWJj:")]
    #[case("geolocation=(self);on=?1")]
    #[case("geolocation=(self);since=@1659578233")]
    #[case("geolocation=(self);label=%\"caf%c3%a9\"")]
    fn any_bare_item_is_a_parameter_value(#[case] value: &str) {
        let v = validate_permissions_policy(value);
        assert!(v.is_empty(), "unexpected finding for {:?}: {:?}", value, v);
    }

    #[rstest]
    fn an_uppercase_parameter_key_is_not_report_to() {
        // A key cannot hold an uppercase letter, so this is a parse failure
        // rather than a misspelled `report-to` whose value needs checking.
        let v = validate_permissions_policy("geolocation=(self);Report-To=\"endpoint\"");
        assert_eq!(v.len(), 1, "{v:?}");
        assert!(v[0].contains("invalid parameter 'Report-To'"), "{}", v[0]);
    }

    #[test]
    fn report_to_quoted_is_ok() {
        let rule = PermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "permissions_policy_directives_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "permissions-policy",
            "geolocation=(self);report-to=\"endpoint\"",
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
    fn feature_part_params_ignored() {
        // a semicolon before the '=' with its own '=' makes the member malformed and should be rejected
        let rule = PermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "permissions_policy_directives_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "permissions-policy",
            "geolocation;meta=1=(self)",
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
    fn decimal_number_value_is_rejected() {
        let rule = PermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "permissions_policy_directives_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "permissions-policy",
            "geolocation=1.2",
        )]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("numeric value"));
    }

    #[test]
    fn byte_sequence_is_rejected() {
        let rule = PermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "permissions_policy_directives_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "permissions-policy",
            "geolocation=:YWJj:",
        )]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        assert!(v.unwrap().message.contains("byte-sequence"));
    }

    #[test]
    fn param_with_number_value_is_ok() {
        let rule = PermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "permissions_policy_directives_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "permissions-policy",
            "geolocation=(self);foo=1",
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
    fn bare_param_is_ok() {
        let rule = PermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "permissions_policy_directives_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "permissions-policy",
            "geolocation=(self);foo",
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
    fn param_with_quoted_value_is_ok() {
        let rule = PermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "permissions_policy_directives_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "permissions-policy",
            "geolocation=(self);foo=\"bar\"",
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
    fn a_bare_token_that_is_not_star_or_self_is_not_an_allowlist() {
        let rule = PermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "permissions_policy_directives_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "permissions-policy",
            "geolocation=feat:sub/1.2-_",
        )]);

        let v = crate::test_helpers::run_rule(
            &rule,
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
        let rule = PermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "permissions_policy_directives_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "permissions-policy",
            "geolocation=(self);*=1",
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
    fn invalid_param_name_uppercase_is_rejected() {
        let rule = PermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "permissions_policy_directives_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "permissions-policy",
            "geolocation=(self);Foo=1",
        )]);

        let v = crate::test_helpers::run_rule(
            &rule,
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
        let rule = PermissionsPolicyDirectivesValid;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "permissions-policy",
            "1feature=(self)",
        )]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
    }

    #[test]
    fn empty_header_value_is_violation() {
        let rule = PermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "permissions_policy_directives_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("permissions-policy", "")]);

        let v = crate::test_helpers::run_rule(
            &rule,
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
        let rule = PermissionsPolicyDirectivesValid;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("permissions-policy", value)]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(
            v.is_some_and(|v| v.message.contains("is given more than once")),
            "{value:?}"
        );
    }

    fn judge_all(value: &str) -> Vec<Violation> {
        let rule = PermissionsPolicyDirectivesValid;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_pairs(&[("permissions-policy", value)]);
        crate::test_helpers::run_rule_all(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
    }

    /// A member that parses and is then ignored costs one directive, and § 5.2
    /// leaves the rest of the policy enforced -- so every such member is its own
    /// finding. Three here: a Boolean value, a Token that is not one § 5.2 names,
    /// and a feature given twice. Only the first used to be reported.
    #[test]
    fn each_unenforceable_directive_is_its_own_finding() {
        let all = judge_all("geolocation=?1, camera=SELF, fullscreen=*, fullscreen=(self)");
        assert_eq!(all.len(), 3, "{all:?}");
        assert!(all[0].message.contains("geolocation"), "{}", all[0].message);
        assert!(all[1].message.contains("camera"), "{}", all[1].message);
        assert!(
            all[2].message.contains("fullscreen") && all[2].message.contains("more than once"),
            "{}",
            all[2].message
        );
    }

    /// A parse failure is one finding and the only one: § 4.2 discards the whole
    /// field, so there are no surviving directives left to describe -- the
    /// `camera=?1` beside it is not separately unenforceable, it is gone with
    /// everything else.
    #[test]
    fn a_parse_failure_is_the_only_finding() {
        let all = judge_all("Geolocation=(self), camera=?1");
        assert_eq!(all.len(), 1, "{all:?}");
        assert!(
            all[0].message.contains("invalid feature identifier"),
            "{}",
            all[0].message
        );
    }

    /// A bare key is not malformed and this rule used to say it was: § 4.2.2
    /// reads it as the Boolean true, which parses. So the field survives, the
    /// directive does not, and the scan carries on to the next member.
    #[test]
    fn a_bare_key_costs_its_own_directive_only() {
        let all = judge_all("geolocation, camera=?1");
        assert_eq!(all.len(), 2, "{all:?}");
        assert!(
            all[0].message.contains("the Boolean true"),
            "{}",
            all[0].message
        );
        assert!(all[1].message.contains("camera"), "{}", all[1].message);
    }

    /// Field lines are joined before parsing, as § 4.2 requires, so a Dictionary
    /// spread across lines is one Dictionary -- including for the duplicate
    /// check, which per-line validation could never have seen.
    #[test]
    fn field_lines_are_joined_before_parsing() {
        use hyper::header::HeaderValue;
        let rule = PermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);

        let mut ok = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = hyper::HeaderMap::new();
        hm.append(
            "permissions-policy",
            HeaderValue::from_static("geolocation=*"),
        );
        hm.append("permissions-policy", HeaderValue::from_static("camera=()"));
        ok.response.as_mut().unwrap().headers = hm;
        assert!(crate::test_helpers::run_rule(
            &rule,
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
        let v = crate::test_helpers::run_rule(
            &rule,
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
        let rule = PermissionsPolicyDirectivesValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[
            "permissions_policy_directives_valid",
        ]);

        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers = crate::test_helpers::make_headers_from_pairs(&[(
            "permissions-policy",
            "geolocation=(self);a.b_c*=1",
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
    fn quoted_string_with_control_char_is_rejected() {
        // hyper rejects control characters in header values; test validator directly instead
        let res = validate_permissions_policy("geolocation=\"a\u{0001}\"");
        assert_eq!(res.len(), 1, "{res:?}");
        // top-level control character check runs first
        assert!(res[0].contains("control characters"), "{}", res[0]);
    }
}
