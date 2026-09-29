// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::auth_param::AUTH_PARAM_EQUALS_MISSING;
use crate::violations::auth_scheme::RFC_9110_11_2;
use crate::violations::digest_credentials::{
    DIGEST_CREDENTIALS_PARAMETER_EMPTY, DIGEST_CREDENTIALS_PARAMETER_MISSING,
    DIGEST_CREDENTIALS_QUOTING_INVALID, RFC_2617_3_2_2, RFC_7616_3_4,
};
use crate::violations::ext_value::{
    EXT_VALUE_CHARSET_FORBIDDEN, EXT_VALUE_MALFORMED, RFC_8187_3_2_1,
};
use crate::violations::list::{auth_param_member, LIST_MEMBER_EMPTY, RFC_9110_5_6_1_1};
use crate::violations::quoted_pair::QUOTED_PAIR_MALFORMED;
use crate::violations::quoted_string::{
    quoted_string_defect, QUOTED_STRING_CONTROL_CHARACTER_FORBIDDEN,
    QUOTED_STRING_DELIMITER_MISSING, QUOTED_STRING_QUOTE_ESCAPE_MISSING, RFC_9110_5_6_4,
};
use crate::violations::token::{
    token_character, RFC_9110_5_6_2, TOKEN_CHARACTER_FORBIDDEN, TOKEN_EMPTY,
    TOKEN_WHITESPACE_OR_CONTROL_FORBIDDEN,
};
use crate::violations::ViolationDef;

pub struct DigestAuthValid;

/// The eight defects an `auth-param` can have that are not RFC 7616's.
///
/// `auth-param = token BWS "=" BWS ( token / quoted-string )` is RFC 9110
/// § 11.2's, imported by RFC 7616 unchanged, so a name holding a `@` and a
/// value that does not close its DQUOTE are the same defects
/// `www_authenticate_challenge_syntax` and `authorization_credentials_valid`
/// already report. **This closes the authentication cluster's grammar half**:
/// every rule in it now answers with the shared ids, and what each still writes
/// is what its own scheme means.
///
/// Everything RFC 7616 says about *Digest* stays here and stays at the rule's
/// severity: which five parameters a credential cannot be verified without,
/// that a `qop` obliges a `cnonce` and an `nc`, and § 3.4's two historical
/// quoting lists — which are requirements about *which spelling* a
/// well-formed value uses, not about whether it is well formed.
///
/// [`crate::helpers::auth::parse_auth_params`] is typed as well, so the list
/// construct's empty member and the two `token` verdicts about a name arrive
/// named from the reader — which is where they were always decided. Its fourth
/// verdict stays this production's: § 11.2 writes `auth-param = token BWS "="
/// BWS ( token / quoted-string )`, so a member with no `=` breaks *that*
/// sentence, and `parameter_equals_missing` carries § 5.6.6's about a
/// production with no `BWS` in it.
/// The document that defines the encoding, naming the fields that carry it.
const RFC_8187_B: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 8187",
    section: Some("B"),
    url: "https://www.rfc-editor.org/rfc/rfc8187.html#appendix-B",
    note: "The implementation report, which lists the four header fields using this \
           encoding — `Authentication-Control`, this one, `Content-Disposition` and \
           `Link`. What says the document in force for a `username*` is RFC 8187 and \
           not the RFC 5987 that RFC 7616 named in 2015",
};

static DECLARED: &[&ViolationDef] = &[
    &AUTH_PARAM_EQUALS_MISSING,
    &DIGEST_CREDENTIALS_PARAMETER_MISSING,
    &DIGEST_CREDENTIALS_PARAMETER_EMPTY,
    &DIGEST_CREDENTIALS_QUOTING_INVALID,
    &LIST_MEMBER_EMPTY,
    &TOKEN_EMPTY,
    &TOKEN_CHARACTER_FORBIDDEN,
    &TOKEN_WHITESPACE_OR_CONTROL_FORBIDDEN,
    &QUOTED_STRING_DELIMITER_MISSING,
    &QUOTED_PAIR_MALFORMED,
    &QUOTED_STRING_QUOTE_ESCAPE_MISSING,
    &QUOTED_STRING_CONTROL_CHARACTER_FORBIDDEN,
    &EXT_VALUE_MALFORMED,
    &EXT_VALUE_CHARSET_FORBIDDEN,
];

impl RuleMeta for DigestAuthValid {
    fn id(&self) -> &'static str {
        "digest_auth_valid"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn description(&self) -> &'static str {
        "Digest credentials must include the required auth-params and use syntactically valid tokens or quoted-strings. This rule checks a `Digest` credential for presence of required fields and basic syntactic validity (e.g., `username`, `realm`, `nonce`, `uri`, `response`), in either field that carries one: RFC 7616 §3.8 gives the scheme's proxy half a section of its own and says the client *\"MUST then reissue the request with a Proxy-Authorization header field, with parameters as specified for the Authorization header field\"*, so a `Proxy-Authorization: Digest ...` is read by the same parameters and each finding names the field it read.\n\n**`cnonce` and `nc` are demanded exactly where the credential's own `qop` makes the demand observable.** RFC 7616 §3.4 marks each *\"MUST be used by all implementations\"*; RFC 2617 computes a qop-less response without either and makes both conditional on a qop directive. A credential that carries `qop` is inside both documents' requirements at once — and both compute the `response` value over `cnonce` and `nc`, so their absence leaves the credential unverifiable by the recipient it was written for. A credential with no `qop` is RFC 2617's older shape and neither is demanded of it: RFC 7616 alone would ask for them, but rejecting the qop-less form outright would reject credentials the obsolete document defines and deployed servers still verify, and no observable line short of `qop` separates the two vintages.\n\n**§3.4's two per-parameter quoting MUSTs are enforced in both directions.** A sender *\"MUST only generate the quoted string syntax\"* for `username`, `realm`, `nonce`, `uri`, `response`, `cnonce` and `opaque`, and *\"MUST NOT\"* for `algorithm`, `qop` and `nc` — for historical reasons, which is the point: recipients of each parameter were deployed against one spelling, so the wrong spelling is a credential some verifiers will not read. An unquoted `uri` was deliberately accepted here for a long time and no longer is. `username*`, `userhash` and unknown extension parameters are in neither list, so only the spelling they arrived in is judged.\n\nServers and clients relying on Digest authentication may behave incorrectly when required parameters are missing or malformed."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            RFC_7616_3_4,
            RFC_2617_3_2_2,
            RFC_8187_3_2_1,
            RFC_8187_B,
            RFC_9110_11_2,
            RFC_9110_5_6_1_1,
            RFC_9110_5_6_2,
            RFC_9110_5_6_4,
        ]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    fn party(&self) -> crate::rules::RuleParty {
        crate::rules::RuleParty::Presumed(crate::lint::Party::Client)
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "GET /protected HTTP/1.1\nAuthorization: Digest username=\"Mufasa\", realm=\"test\", nonce=\"abc\", uri=\"/protected\", response=\"d41d8cd98f00b204e9800998ecf8427e\"",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(missing response)"),
                snippet: "GET /protected HTTP/1.1\nAuthorization: Digest username=\"Mufasa\", realm=\"test\", nonce=\"abc\", uri=\"/protected\"",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(username unquoted — §3.4 admits only the quoted string syntax for it)"),
                snippet: "GET /protected HTTP/1.1\nAuthorization: Digest username=Mu!fasa, realm=\"test\", nonce=\"abc\", uri=\"/protected\", response=\"d41d8c\"",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(qop sent with no cnonce or nc — the response value is computed over both)"),
                snippet: "GET /protected HTTP/1.1\nAuthorization: Digest username=\"Mufasa\", realm=\"test\", nonce=\"abc\", uri=\"/protected\", response=\"d41d8c\", qop=auth",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(username* is §3.4's answer for a name a quoted-string cannot hold)"),
                snippet: "GET /protected HTTP/1.1\nAuthorization: Digest username*=UTF-8''%c3%bcser, realm=\"test\", nonce=\"abc\", uri=\"/protected\", response=\"d41d8c\"",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(a username* whose percent-escape is not hexadecimal)"),
                snippet: "GET /protected HTTP/1.1\nAuthorization: Digest username*=UTF-8''%zz, realm=\"test\", nonce=\"abc\", uri=\"/protected\", response=\"d41d8c\"",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(the field RFC 7616 §3.8 reissues the same parameters in)"),
                snippet: "GET /protected HTTP/1.1\nProxy-Authorization: Digest username=\"Mufasa\", realm=\"test\", nonce=\"abc\", uri=\"/protected\"",
            },
        ]
    }
}

impl Rule for DigestAuthValid {
    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        let mut out = Vec::new();
        // Read as octets: an octet outside visible US-ASCII belongs to
        // whichever of this scheme's parts it landed in -- an `auth-param`
        // name that is a `token`, a value that is a `quoted-string` -- and
        // the reader that refused the value outright reported it as the
        // field's encoding instead.
        // Both fields § 11 writes as `credentials`. RFC 7616 § 3.8 gives
        // the scheme's proxy half a section of its own and says the
        // credential is the one § 3.4 already describes: the client "MUST
        // then reissue the request with a Proxy-Authorization header field,
        // with parameters as specified for the Authorization header field".
        // cite(RFC 7616 § 3.8): "The Digest Authentication scheme can also be used for authenticating users to proxies, proxies to proxies, or proxies to origin servers by use of the Proxy-Authenticate and Proxy-Authorization header fields."
        for (shown, s) in crate::helpers::auth::credentials_field_lines(&tx.request.headers) {
            let s = crate::helpers::headers::trim_ows(&s);
            if s.is_empty() {
                continue;
            }
            // Only care about the Digest scheme; auth-scheme names are
            // matched case-insensitively.
            // cite(RFC 9110 § 11.1): "It uses a case-insensitive token to identify the authentication scheme"
            let (scheme, tail) = crate::helpers::auth::split_scheme_and_tail(s);
            if !scheme.eq_ignore_ascii_case("digest") {
                continue;
            }
            let Some(rest) = tail else {
                out.push(ctx.report_with(
                    &DIGEST_CREDENTIALS_PARAMETER_MISSING,
                    format!("{shown} Digest scheme missing parameters"),
                ));
                continue;
            };
            out.extend(credential_defects(shown, rest, ctx));
        }
        out
    }
}

/// Every defect of one Digest credential's parameter list, in the order the
/// parameters were written.
///
/// **A malformed member does not end the reading.** The parse sets it aside
/// and this answers for the rest, which is the other half of what the body
/// returning at its first finding hid: `username="u", realm=r, flag` was a
/// finding about `flag` alone. The malformed members are the framework
/// reader's, which reports each of them; this names the first, the sentence it
/// has always had, and whether it should name any is the double report's own
/// question.
///
/// **A parameter written without its `=` is malformed and not missing**, and
/// the required-parameter walk says so by skipping it: `Digest username,
/// realm="r", …` has a `username`, and telling the sender to add one would
/// send them to write it twice.
fn credential_defects(
    shown: &str,
    rest: &str,
    ctx: &crate::rules::RuleContext<'_>,
) -> Vec<Violation> {
    let mut out = Vec::new();
    let (pairs, defects) = crate::helpers::auth::parse_auth_params_in_order(rest);
    let map: std::collections::HashMap<&str, &str> = pairs
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    // The reader is typed and its mapping is total: an empty
    // member is the list's, an empty name and a bad character
    // are the `token`'s, and a member with no `=` is
    // `auth-param`'s own — § 11.2's sentence rather than
    // § 5.6.6's, which describes a construct with no `BWS` in
    // it.
    if let Some(defect) = defects.first().copied() {
        let message = format!("Invalid Digest auth parameters: {}", defect.message());
        out.push(ctx.report_with(auth_param_member(defect), message));
    }
    let written_without_value = |k: &str| {
        defects.iter().any(|d| {
            matches!(d, crate::helpers::auth::AuthParamsDefect::ValueMissing(n) if n.eq_ignore_ascii_case(k))
        })
    };
    // Names reported empty below, so the per-parameter reading does not also
    // tell the sender how to spell a value that is not there.
    let mut answered: Vec<&str> = Vec::new();

    // Required fields: username, realm, nonce, uri, response. §3.4 lists the
    // parameters and names the consequence for missing required ones, but
    // labels no "required" set; these five are the ones the response
    // computation (§3.4.1) cannot be verified without whatever the
    // credential's vintage. cnonce and nc are demanded below, behind the
    // observable line that keeps RFC 2617-style credentials checkable.
    // cite(RFC 7616 § 3.4): "If a parameter or its value is improper, or required parameters are missing, the proper response is a 4xx error code."
    let required = ["username", "realm", "nonce", "uri", "response"];
    for &k in &required {
        // **`username*` is how § 3.4 says to send a username
        // the `quoted-string` production cannot hold**, so a
        // credential carrying it carries the parameter. Asked
        // for `username` by name, this walk reported the one
        // shape the section prescribes — and the repair it
        // named, adding a `username` beside the `username*`,
        // is the shape the same paragraph calls an error.
        //
        // Sending both is that error and is not reported here
        // yet; what this says is only that the extended
        // spelling satisfies the requirement, which is the
        // half § 3.4 states about a credential carrying one.
        //
        // cite(RFC 7616 § 3.4, label: username-quoted): "If the username contains characters not allowed inside the ABNF quoted-string production, the username* parameter can be used."
        if k == "username" && map.contains_key("username*") {
            continue;
        }
        if written_without_value(k) {
            continue;
        }
        match map.get(k) {
            Some(v) => {
                // treat empty unquoted values or quoted-strings with empty inner content
                let is_empty = if v.is_empty() {
                    true
                } else if v.starts_with('"') {
                    // if quoted-string is syntactically invalid, default to 'false' so
                    // it will be reported by the later quoted-string validation
                    crate::helpers::quoted_string::quoted_string_inner_trimmed_is_empty(v)
                        .unwrap_or_default()
                } else {
                    false
                };

                if is_empty {
                    answered.push(k);
                    out.push(ctx.report_with(
                        &DIGEST_CREDENTIALS_PARAMETER_EMPTY,
                        format!("Digest {shown} sends required parameter '{k}' with nothing in it"),
                    ));
                }
            }
            None => out.push(ctx.report_with(
                &DIGEST_CREDENTIALS_PARAMETER_MISSING,
                format!("Digest {shown} is missing required parameter '{k}' (RFC 7616 \u{a7}3.4)"),
            )),
        }
    }
    // The two parameters RFC 7616 §3.4 marks "MUST be used by all
    // implementations", demanded where the credential's own qop makes
    // the demand observable. RFC 2617 computes a qop-less response
    // without either, so requiring them of every Digest credential
    // would reject that document's otherwise-checkable shape — but a
    // credential that *carries* qop is inside both documents' MUSTs at
    // once: RFC 2617's conditional is met by the message itself, and
    // both compute the response value over cnonce and nc, so their
    // absence leaves the response unverifiable by the recipient it was
    // written for. The qop-less decline is published in
    // `description()`.
    // cite(RFC 7616 § 3.4, label: cnonce): "This parameter MUST be used by all implementations."
    // cite(RFC 2617 § 3.2.2): "This MUST be specified if a qop directive is sent (see above), and MUST NOT be specified if the server did not send a qop directive in the WWW-Authenticate header field."
    if map.contains_key("qop") {
        for &k in &["cnonce", "nc"] {
            if !map.contains_key(k) && !written_without_value(k) {
                out.push(ctx.report_with(&DIGEST_CREDENTIALS_PARAMETER_MISSING, format!(
                    "Digest {shown} sends 'qop' and no '{k}': RFC 7616 \u{a7}3.4 marks the parameter \"MUST be used by all implementations\", RFC 2617 \u{a7}3.2.2 requires it whenever a qop directive is sent, and both documents compute the response value over it, so without it the credential cannot be verified"
                )));
            }
        }
    }

    // Every parameter, in the order written: the walk used to be over the map,
    // and a hash map's order is its own, so which of two defects a sender was
    // told about was the hasher's choice.
    for (k, v) in &pairs {
        if answered.contains(&k.as_str()) {
            continue;
        }
        out.extend(parameter_defect(shown, k, v, ctx));
    }
    out
}

/// The first thing one parameter of a Digest credential fails to be, or
/// `None`: its name's `token`, § 3.4's spelling of it, `username*`'s
/// `ext-value`, and its value's own production.
///
/// **One parameter, one finding**, and every parameter asked: the body used
/// to return from the whole credential at the first parameter that failed, so
/// `realm=r, nonce=n` was one finding and the second arrived once the first was
/// fixed. The checks here are about one value and an earlier one answers for
/// it: a `nonce` written unquoted is not also asked whether its octets are a
/// `token`.
fn parameter_defect(
    shown: &str,
    k: &str,
    v: &str,
    ctx: &crate::rules::RuleContext<'_>,
) -> Option<Violation> {
    // param names must be tokens
    // An `auth-param` name is a `token`, which is
    // § 5.6.2's production imported unchanged --
    // so the two ids here are the ones every
    // other reader of it answers with.
    //
    // **This branch still cannot fire**, and the
    // reason is in the parse rather than anywhere
    // in this document: `parse_auth_params`
    // measures the name against the same reader
    // and sets the member aside, so a `user@name`
    // is answered there and never reaches the map. It is kept because the
    // two answers now agree by construction --
    // the helper's mapping hands back this same
    // id -- and because a reader that stopped
    // measuring the name would leave this the
    // only check of it.
    if let Some(inv) = crate::helpers::token::find_invalid_token_char(k) {
        return Some(ctx.report_with(
            token_character(inv),
            format!("Invalid character '{}' in Digest auth-param name", inv),
        ));
    }
    // §3.4's two per-parameter quoting MUSTs, enforced in both
    // directions. The historical reason is the point: recipients
    // of these parameters were deployed against one spelling each,
    // so the wrong spelling is a credential some verifiers will
    // not read. The seven-name list is why the old `uri` branch —
    // which deliberately accepted an unquoted value — is gone: an
    // unquoted uri is exactly what the first sentence forbids.
    // `username*`, `userhash` and unknown extensions are in
    // neither list, and only their present spelling is judged.
    // cite(RFC 7616 § 3.4): "For historical reasons, a sender MUST only generate the quoted string syntax for the following parameters: username, realm, nonce, uri, response, cnonce, and opaque."
    // cite(RFC 7616 § 3.4): "For historical reasons, a sender MUST NOT generate the quoted string syntax for the following parameters: algorithm, qop, and nc."
    const MUST_QUOTE: &[&str] = &[
        "username", "realm", "nonce", "uri", "response", "cnonce", "opaque",
    ];
    const MUST_NOT_QUOTE: &[&str] = &["algorithm", "qop", "nc"];

    let quoted = v.starts_with('"');
    if MUST_QUOTE.contains(&k) && !quoted {
        return Some(ctx.report_with(&DIGEST_CREDENTIALS_QUOTING_INVALID, format!(
                "Digest {shown} sends '{k}' unquoted, and RFC 7616 \u{a7}3.4 admits only the quoted string syntax for it (\"a sender MUST only generate the quoted string syntax for the following parameters: username, realm, nonce, uri, response, cnonce, and opaque\")"
            )));
    }
    if MUST_NOT_QUOTE.contains(&k) && quoted {
        return Some(ctx.report_with(&DIGEST_CREDENTIALS_QUOTING_INVALID, format!(
                "Digest {shown} sends '{k}' as a quoted string, and RFC 7616 \u{a7}3.4 forbids that spelling for it (\"a sender MUST NOT generate the quoted string syntax for the following parameters: algorithm, qop, and nc\")"
            )));
    }

    // `username*` carries "the extended notation defined in
    // [RFC5987]", which RFC 8187 obsoletes with the same
    // `ext-value`, `value-chars`, `pct-encoded` and `attr-char`
    // productions byte for byte — and RFC 8187's own
    // implementation report names this field as one of the four
    // that use the encoding, so the document in force is the one
    // read here. The parameter was excluded from both quoting
    // lists above and then measured as a `token`, which is what
    // `UTF-8''%zz` is: every octet an `ext-value` prints is a
    // `tchar`, so the token walk could never refuse one.
    //
    // **By name, and `Link`'s reading is by shape**, which is the
    // difference between the two documents rather than an
    // inconsistency here: RFC 8187 § 3.2.1 says the trailing
    // asterisk is "just a convention" and that a field has to
    // specify the extended value in its own definition. RFC 8288
    // does that for every parameter at once, in its parsing
    // algorithm; RFC 7616 does it for this one parameter, in
    // prose. So a Digest `foo*` is an ordinary extension
    // parameter and stays unread.
    //
    // cite(RFC 7616 § 3.4, label: username-star): "If the userhash parameter value is set "false" and the username contains characters not allowed inside the ABNF quoted-string production, the user's name can be sent with this parameter, using the extended notation defined in [RFC5987]."
    // cite(RFC 8187 § B): ""Authorization" (as used in HTTP Digest Authentication, defined in [RFC7616]),"
    if k == "username*" {
        if let Err(why) = crate::helpers::parameter::validate_ext_value(v) {
            return Some(ctx.report_with(
                &EXT_VALUE_MALFORMED,
                format!(
                    "Digest {shown} sends username*='{v}', which \
                     does not derive from ext-value: {why}"
                ),
            ));
        }
        if let Some(charset) = crate::helpers::parameter::ext_value_charset_reserved(v) {
            return Some(ctx.report_with(
                &EXT_VALUE_CHARSET_FORBIDDEN,
                format!(
                    "Digest {shown} sends username*='{v}', naming \
                     the character encoding '{charset}', which RFC 8187 \
                     §3.2.1 reserves for future use and forbids a \
                     producer to write; a recipient built to that \
                     document decodes UTF-8 alone"
                ),
            ));
        }
    }

    // A value that opens with a quote is validated as a quoted-string
    // (grammar helper-owned, RFC 9110 §5.6.4).
    if quoted {
        if let Err(defect) = crate::helpers::quoted_string::check_quoted_string(v) {
            return Some(ctx.report_with(
                quoted_string_defect(defect),
                format!(
                    "Invalid quoted-string in Digest auth-param '{}': {}",
                    k,
                    defect.message(v)
                ),
            ));
        }
    } else {
        // Unquoted values are tokens. The `uri` carve-out that
        // stood here (allow anything without control characters)
        // is unreachable now: an unquoted `uri` returns above.
        if let Some(inv) = crate::helpers::token::find_invalid_token_char(v) {
            return Some(ctx.report_with(
                token_character(inv),
                format!(
                    "Invalid character '{}' in Digest auth-param value for '{}'",
                    inv, k
                ),
            ));
        }
    }
    None
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &DigestAuthValid;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// **Both fields RFC 7616 § 3.8 reissues the same parameters in, and each
    /// finding names the one it read.**
    ///
    /// `Proxy-Authorization: Digest ...` missing `response` drew nothing, where
    /// the identical credential in `Authorization` is a finding. § 3.8 does not
    /// restate the parameters for the proxy exchange; it says the client
    /// reissues "with parameters as specified for the Authorization header
    /// field", so there is one reading and it was pointed at one field. The
    /// message is asserted because every arm of it said "Digest Authorization"
    /// outright.
    #[rstest]
    #[case("authorization", "Authorization")]
    #[case("proxy-authorization", "Proxy-Authorization")]
    fn a_digest_credential_is_read_in_both_fields_that_carry_it(
        #[case] key: &str,
        #[case] shown: &str,
    ) {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            key,
            "Digest username=\"Mufasa\", realm=\"test\", nonce=\"abc\", uri=\"/protected\"",
        )]);
        let v = crate::test_helpers::run_rule(
            &DigestAuthValid,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&["digest_auth_valid"]),
        )
        .unwrap_or_else(|| panic!("nothing reported for {key}"));
        assert_eq!(v.violation, "digest_credentials_parameter_missing");
        assert!(
            v.message.contains(shown),
            "a finding about {key} says {:?}, which does not name the field it read",
            v.message
        );
    }

    // The conforming fixtures write each parameter in the spelling §3.4's two
    // historical-reasons MUSTs assign it — the seven quoted, `algorithm`, `qop`
    // and `nc` bare. The fixtures used to write everything unquoted, which is
    // the tolerance RULECITES P37 removed.
    #[rstest]
    #[case(
        Some(
            "Digest username=\"Mufasa\", realm=\"test\", nonce=\"abc\", uri=\"/\", response=\"d\""
        ),
        false
    )]
    #[case(
        Some("Digest username=\"Mufasa\", realm=\"test\", nonce=\"abc\", uri=\"/\", response=\"d\", algorithm=MD5"),
        false
    )]
    // RFC 7616's full shape: qop with cnonce and nc beside it.
    #[case(
        Some("Digest username=\"Mufasa\", realm=\"test\", nonce=\"abc\", uri=\"/\", response=\"d\", qop=auth, cnonce=\"xyz\", nc=00000001"),
        false
    )]
    // qop without nc, and qop without cnonce: both documents' MUSTs at once.
    #[case(
        Some("Digest username=\"Mufasa\", realm=\"test\", nonce=\"abc\", uri=\"/\", response=\"d\", qop=auth, cnonce=\"xyz\""),
        true
    )]
    #[case(
        Some("Digest username=\"Mufasa\", realm=\"test\", nonce=\"abc\", uri=\"/\", response=\"d\", qop=auth, nc=00000001"),
        true
    )]
    // The spelling findings, one per direction: an unquoted `uri` — the value
    // the old rule deliberately accepted — and a quoted `nc`.
    #[case(
        Some("Digest username=\"Mufasa\", realm=\"test\", nonce=\"abc\", uri=/, response=\"d\""),
        true
    )]
    #[case(
        Some("Digest username=\"Mufasa\", realm=\"test\", nonce=\"abc\", uri=\"/\", response=\"d\", qop=auth, cnonce=\"xyz\", nc=\"00000001\""),
        true
    )]
    #[case(
        Some("Digest username=\"Mufasa\", realm=\"test\", nonce=\"abc\", uri=\"/\""),
        true
    )]
    #[case(
        Some("Digest username=, realm=\"test\", nonce=\"abc\", uri=\"/\", response=\"d\""),
        true
    )]
    #[case(
        Some("Digest username=\"Mufasa\", realm=\"test\", nonce=a@bad, uri=\"/\", response=\"d\""),
        true
    )]
    // A conforming `username*` alone, which is § 3.4's own answer for a name the
    // `quoted-string` production cannot hold; and an ordinary extension
    // parameter whose name happens to end in an asterisk, which RFC 7616
    // defines no extended notation for and which stays an unread token.
    #[case(
        Some("Digest username*=UTF-8''%c3%bcser, realm=\"r\", nonce=\"n\", uri=\"/\", response=\"d\""),
        false
    )]
    #[case(
        Some("Digest username=\"u\", foo*=UTF-8x, realm=\"r\", nonce=\"n\", uri=\"/\", response=\"d\""),
        false
    )]
    #[case(Some("Basic abc"), false)]
    #[case(Some("Digest"), true)]
    #[case(
        Some("Digest username=\"Mufasa, realm=test, nonce=abc, uri=/, response=d"),
        true
    )]
    #[case(None, false)]
    fn check_digest_authorization(
        #[case] header: Option<&str>,
        #[case] expect_violation: bool,
    ) -> anyhow::Result<()> {
        let rule = DigestAuthValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&["digest_auth_valid"]);

        let mut tx = crate::test_helpers::make_test_transaction();
        if let Some(h) = header {
            tx.request
                .headers
                .append("authorization", h.parse().unwrap());
        }

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(v.is_some());
        } else {
            assert!(v.is_none());
        }
        Ok(())
    }

    /// Every finding this rule makes and the id it draws, in two groups. The
    /// first four are the `auth-param`'s grammar rather than Digest's, and a
    /// `WWW-Authenticate` reports them the same way; the last four are RFC
    /// 7616 § 3.4's, about which parameters a credential owes and how each is
    /// spelled. Nothing in the rule is untyped now.
    #[rstest]
    // A bad *name* is answered by the reader rather than by this rule's own
    // check -- `parse_auth_params` measures it two lines earlier -- and since
    // that reader is typed, the same id arrives either way.
    #[case::name_character(
        "Digest user@name=abc, realm=\"r\", nonce=\"n\", uri=\"/\", response=\"d\"",
        "token_character_forbidden"
    )]
    #[case::empty_member("Digest username=\"u\", , realm=\"r\"", "list_member_empty")]
    #[case::empty_name("Digest =abc, realm=\"r\"", "token_empty")]
    #[case::value_missing("Digest username, realm=\"r\"", "auth_param_equals_missing")]
    #[case::value_character("Digest username=\"u\", realm=\"r\", nonce=\"n\", uri=\"/\", response=\"d\", algorithm=M@D5", "token_character_forbidden")]
    #[case::unterminated_quote(
        "Digest username=\"u\", realm=\"r\", nonce=\"n\", uri=\"/\", response=\"d\", opaque=\"abc",
        "quoted_string_delimiter_missing"
    )]
    #[case::missing_required(
        "Digest realm=\"r\", nonce=\"n\", uri=\"/\", response=\"d\"",
        "digest_credentials_parameter_missing"
    )]
    #[case::qop_without_cnonce("Digest username=\"u\", realm=\"r\", nonce=\"n\", uri=\"/\", response=\"d\", qop=auth, nc=00000001", "digest_credentials_parameter_missing")]
    #[case::must_quote(
        "Digest username=\"u\", realm=\"r\", nonce=\"n\", uri=/, response=\"d\"",
        "digest_credentials_quoting_invalid"
    )]
    #[case::must_not_quote("Digest username=\"u\", realm=\"r\", nonce=\"n\", uri=\"/\", response=\"d\", qop=\"auth\", cnonce=\"c\", nc=00000001", "digest_credentials_quoting_invalid")]
    // `username*` is the one parameter this document defines in RFC 8187's
    // extended notation, and every octet an `ext-value` prints is a `tchar` --
    // so before it was read as one, the token walk was the whole of what
    // measured these values and neither of them moved it.
    #[case::username_star_malformed(
        "Digest username*=UTF-8''%zz, realm=\"r\", nonce=\"n\", uri=\"/\", response=\"d\"",
        "ext_value_malformed"
    )]
    #[case::username_star_charset(
        "Digest username*=iso-8859-1'en'%A3, realm=\"r\", nonce=\"n\", uri=\"/\", response=\"d\"",
        "ext_value_charset_forbidden"
    )]
    fn the_auth_params_grammar_is_not_digests(#[case] header: &str, #[case] violation: &str) {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request
            .headers
            .append("authorization", header.parse().expect("a field value"));
        let finding = crate::test_helpers::run_rule(
            &DigestAuthValid,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&["digest_auth_valid"]),
        )
        .unwrap_or_else(|| panic!("expected a finding for {header:?}"));
        assert_eq!(finding.violation, violation, "for {header:?}");
    }

    #[test]
    fn invalid_param_name_reports_violation() -> anyhow::Result<()> {
        let rule = DigestAuthValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&["digest_auth_valid"]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers.append(
            "authorization",
            "Digest user@name=abc, realm=test, nonce=abc, uri=/, response=d"
                .parse()
                .unwrap(),
        );

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        let v = v.unwrap();
        assert!(v.message.contains("Invalid character"));
        Ok(())
    }

    #[test]
    fn lowercase_scheme_is_accepted() -> anyhow::Result<()> {
        let rule = DigestAuthValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&["digest_auth_valid"]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers.append(
            "authorization",
            "digest username=\"Mufasa\", realm=\"test\", nonce=\"abc\", uri=\"/\", response=\"d\""
                .parse()
                .unwrap(),
        );

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn parse_params_missing_value_reports_violation() -> anyhow::Result<()> {
        let rule = DigestAuthValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&["digest_auth_valid"]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers.append(
            "authorization",
            "Digest username, realm=test, nonce=abc, uri=/, response=d"
                .parse()
                .unwrap(),
        );

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        let v = v.unwrap();
        assert!(v.message.contains("Invalid Digest auth parameters"));
        Ok(())
    }

    #[test]
    fn non_utf8_header_reports_violation() -> anyhow::Result<()> {
        let rule = DigestAuthValid;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers.append(
            "authorization",
            hyper::header::HeaderValue::from_bytes(b"Digest \xff").unwrap(),
        );
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn required_param_quoted_empty_reports_violation() -> anyhow::Result<()> {
        let rule = DigestAuthValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&["digest_auth_valid"]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers.append(
            "authorization",
            "Digest username=\"\", realm=\"test\", nonce=\"abc\", uri=\"/\", response=\"d\""
                .parse()
                .unwrap(),
        );

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        let v = v.unwrap();
        assert!(
            v.message.contains("required parameter")
                || v.message.contains("Invalid Digest auth parameters")
        );
        Ok(())
    }

    #[test]
    fn quoted_string_with_escaped_quote_is_accepted() -> anyhow::Result<()> {
        let rule = DigestAuthValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&["digest_auth_valid"]);

        let mut tx = crate::test_helpers::make_test_transaction();
        // username contains an escaped quote inside the quoted-string which is valid
        tx.request.headers.append(
            "authorization",
            "Digest username=\"Mu\\\"fasa\", realm=\"test\", nonce=\"abc\", uri=\"/\", response=\"d\"".parse().unwrap(),
        );

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn invalid_quoted_string_reports_specific_message() -> anyhow::Result<()> {
        let rule = DigestAuthValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&["digest_auth_valid"]);

        let mut tx = crate::test_helpers::make_test_transaction();
        // username quoted-string missing closing quote should trigger quoted-string validation error
        tx.request.headers.append(
            "authorization",
            "Digest username=\"Mufasa, realm=test, nonce=abc, uri=/, response=d"
                .parse()
                .unwrap(),
        );

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(
            msg.contains("Invalid quoted-string")
                || msg.contains("Invalid Digest auth parameters")
                || msg.contains("required parameter")
        );
        Ok(())
    }

    #[test]
    fn header_value_construction_rejects_control_chars() -> anyhow::Result<()> {
        // Hyper's HeaderValue validation rejects control characters in header values (as per the HTTP
        // specification). Therefore it's not possible to construct a header containing LF/CR to feed
        // through the normal header pipeline; the constructor will return an error. Assert that
        // behavior here so we don't rely on impossible-to-construct inputs.
        use hyper::header::HeaderValue;
        let raw = b"Digest username=Mufasa, realm=test, nonce=abc, uri=/bad\n, response=d";
        let hv = HeaderValue::from_bytes(raw);
        assert!(hv.is_err());
        Ok(())
    }

    #[test]
    fn digest_scheme_with_whitespace_but_no_params_reports_invalid_params() -> anyhow::Result<()> {
        let rule = DigestAuthValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&["digest_auth_valid"]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request
            .headers
            .append("authorization", "Digest    ".parse().unwrap());

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        let v = v.unwrap();
        // message should be non-empty and indicate a problem with parameters
        assert!(!v.message.is_empty());
        Ok(())
    }

    #[test]
    fn digest_scheme_without_params_reports_missing_parameters_message() -> anyhow::Result<()> {
        let rule = DigestAuthValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&["digest_auth_valid"]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request
            .headers
            .append("authorization", "Digest".parse().unwrap());

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        let v = v.unwrap();
        assert!(v.message.contains("missing parameters"));
        Ok(())
    }

    #[test]
    fn invalid_response_value_token_char_reports_violation() -> anyhow::Result<()> {
        let rule = DigestAuthValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&["digest_auth_valid"]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers.append(
            "authorization",
            "Digest username=\"Mufasa\", realm=\"test\", nonce=\"abc\", uri=\"/\", response=\"d\", userhash=tr@e"
                .parse()
                .unwrap(),
        );

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(
            msg.contains("Invalid character") || msg.contains("Invalid Digest auth parameters")
        );
        Ok(())
    }

    #[test]
    fn invalid_quoted_string_extra_chars_reports_violation() -> anyhow::Result<()> {
        let rule = DigestAuthValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&["digest_auth_valid"]);

        let mut tx = crate::test_helpers::make_test_transaction();
        // username quoted-string followed by extra chars should trigger quoted-string validation error
        tx.request.headers.append(
            "authorization",
            "Digest username=\"Mufasa\"x, realm=\"test\", nonce=\"abc\", uri=\"/\", response=\"d\""
                .parse()
                .unwrap(),
        );

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(
            msg.contains("Invalid quoted-string") || msg.contains("Invalid Digest auth parameters")
        );
        Ok(())
    }

    /// **The occurrence this rule grades is the first, and this test asserted
    /// the opposite.** It sent `username=Mufasa, username=` and demanded a
    /// finding about an empty required parameter — which arrived only because
    /// the shared parameter reader inserted into a map and the empty second
    /// occurrence overwrote `Mufasa`. That is not a reading of the credential:
    /// it made what this rule grades depend on the order a sender wrote two
    /// values in, and in the direction where a sender could take a finding away
    /// by *appending* a parameter.
    ///
    /// The empty member is not lost by the change and was never this rule's:
    /// `auth-param`'s value has a floor of one character in both alternatives,
    /// so `username=` is `auth_param_value_empty`, reported about the same
    /// field by `authorization_credentials_valid`. What is asserted here is
    /// only which of the two values §3.4's required-parameter reading is about.
    ///
    /// RFC 9110 § 11.2's MUST against writing the name twice is
    /// `challenge_parameter_duplicated`, and it is deliberately not reported
    /// about a credential — the sentence counts per *challenge* and § 11.4 has
    /// no analogue of one.
    #[rstest]
    // The first is well formed, so §3.4's reading has its parameter.
    #[case(
        r#"Digest username="Mufasa", username=, realm="test", nonce="abc", uri="/", response="d""#,
        None
    )]
    // The other order, where the value that binds is the defective one.
    #[case(
        r#"Digest username=, username="Mufasa", realm="test", nonce="abc", uri="/", response="d""#,
        Some("digest_credentials_parameter_empty")
    )]
    fn the_first_occurrence_of_a_repeated_parameter_is_the_one_graded(
        #[case] value: &str,
        #[case] expected: Option<&str>,
    ) {
        let rule = DigestAuthValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&["digest_auth_valid"]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request
            .headers
            .append("authorization", value.parse().unwrap());

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert_eq!(
            v.map(|v| v.violation),
            expected.map(str::to_string),
            "{value:?}"
        );
    }

    #[test]
    fn multiple_authorization_headers_one_invalid_triggers_violation() -> anyhow::Result<()> {
        let rule = DigestAuthValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&["digest_auth_valid"]);

        let mut tx = crate::test_helpers::make_test_transaction();
        // add a Basic header first, then an invalid Digest (empty response)
        tx.request
            .headers
            .append("authorization", "Basic abc".parse().unwrap());
        tx.request.headers.append(
            "authorization",
            "Digest username=Mufasa, realm=test, nonce=abc, uri=/, response="
                .parse()
                .unwrap(),
        );

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        let v = v.unwrap();
        assert!(
            v.message.contains("required parameter")
                || v.message.contains("Invalid Digest auth parameters")
        );
        Ok(())
    }

    #[test]
    fn multiple_digest_headers_one_invalid_after_valid_triggers_violation() -> anyhow::Result<()> {
        let rule = DigestAuthValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&["digest_auth_valid"]);

        let mut tx = crate::test_helpers::make_test_transaction();
        // first a valid Digest, then an invalid Digest (empty response)
        tx.request.headers.append(
            "authorization",
            "Digest username=\"Alice\", realm=\"test\", nonce=\"abc\", uri=\"/\", response=\"resp1\""
                .parse()
                .unwrap(),
        );
        tx.request.headers.append(
            "authorization",
            "Digest username=Bob, realm=test, nonce=abc, uri=/, response="
                .parse()
                .unwrap(),
        );

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
    fn multiple_digest_headers_all_valid_no_violation() -> anyhow::Result<()> {
        let rule = DigestAuthValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&["digest_auth_valid"]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers.append(
            "authorization",
            "Digest username=\"Alice\", realm=\"test\", nonce=\"abc\", uri=\"/\", response=\"resp1\""
                .parse()
                .unwrap(),
        );
        tx.request.headers.append(
            "authorization",
            "Digest username=\"Bob\", realm=\"test\", nonce=\"def\", uri=\"/\", response=\"resp2\""
                .parse()
                .unwrap(),
        );

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn empty_authorization_header_ignored() {
        let rule = DigestAuthValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&["digest_auth_valid"]);

        let mut tx = crate::test_helpers::make_test_transaction();
        // An empty Authorization value should be ignored
        tx.request
            .headers
            .append("authorization", "".parse().unwrap());
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn unquoted_username_with_space_reports_violation() -> anyhow::Result<()> {
        let rule = DigestAuthValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&["digest_auth_valid"]);

        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers.append(
            "authorization",
            "Digest username=Mu fasa, realm=test, nonce=abc, uri=/, response=d"
                .parse()
                .unwrap(),
        );

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
    fn quoted_string_ends_with_escape_reports_violation() -> anyhow::Result<()> {
        let rule = DigestAuthValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&["digest_auth_valid"]);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers.append(
            "authorization",
            "Digest username=\"Mu\\\", realm=\"test\", nonce=\"abc\", uri=\"/\", response=\"d\""
                .parse()
                .unwrap(),
        );
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(
            msg.contains("Invalid quoted-string")
                || msg.contains("Invalid Digest auth parameters")
                || msg.contains("required parameter")
        );
        Ok(())
    }

    #[test]
    fn required_param_unquoted_empty_reports_violation() -> anyhow::Result<()> {
        let rule = DigestAuthValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&["digest_auth_valid"]);
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers.append(
            "authorization",
            "Digest username=, realm=test, nonce=abc, uri=/, response=d"
                .parse()
                .unwrap(),
        );
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(
            msg.contains("required parameter") || msg.contains("Invalid Digest auth parameters")
        );
        Ok(())
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "digest_auth_valid");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn needs_no_response() {
        let rule = DigestAuthValid;
        assert!(!rule.needs_response());
    }

    /// **Every parameter of a credential, not the first.** The body returned
    /// at the first parameter it found wrong, and it walked a hash map to find
    /// it, so which of two defects a sender was told about was the hasher's
    /// choice and the other arrived once the first was repaired. A malformed
    /// member ended the reading of every well-formed one beside it. Each row
    /// carries defects in two parameters and draws both, in the order the
    /// parameters were written; the last two rows are the controls the repair
    /// keeps -- a parameter written without its `=` is malformed and not
    /// missing, and one reported empty is not also told how to spell itself.
    #[rstest]
    #[case(
        r#"Digest realm=r, nonce="n", uri="/", response="0""#,
        &["digest_credentials_parameter_missing", "digest_credentials_quoting_invalid"]
    )]
    #[case(
        r#"Digest username="u", realm=r, nonce=n, uri="/", response="0""#,
        &["digest_credentials_quoting_invalid", "digest_credentials_quoting_invalid"]
    )]
    #[case(
        r#"Digest username="u", realm=r, nonce="n", uri="/", response="0", flag"#,
        &["auth_param_equals_missing", "digest_credentials_quoting_invalid"]
    )]
    #[case(
        r#"Digest username*=bogus, realm=r, nonce="n", uri="/", response="0""#,
        &["ext_value_malformed", "digest_credentials_quoting_invalid"]
    )]
    #[case(
        r#"Digest username="u", realm="r", nonce="n", uri="/", response="0", qop=auth, nc=00000001, opaque=x"#,
        &["digest_credentials_parameter_missing", "digest_credentials_quoting_invalid"]
    )]
    #[case(
        r#"Digest username, realm="r", nonce="n", uri="/", response="0""#,
        &["auth_param_equals_missing"]
    )]
    #[case(
        r#"Digest username=, realm="r", nonce="n", uri="/", response="0""#,
        &["digest_credentials_parameter_empty"]
    )]
    fn every_parameter_of_a_credential_is_answered_about(
        #[case] value: &str,
        #[case] expected: &[&str],
    ) {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("authorization", value)]);
        let all = crate::test_helpers::run_rule_all(
            &DigestAuthValid,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&["digest_auth_valid"]),
        );
        let ids: Vec<&str> = all.iter().map(|v| v.violation.as_str()).collect();
        assert_eq!(ids, expected, "{value}: {all:?}");
    }
}
