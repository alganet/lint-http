// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::helpers::headers::split_commas_respecting_quotes;

/// Split a WWW-Authenticate header value into "assembled" challenges.
///
/// This function splits top-level comma-separated members (respecting quoted-strings)
/// and groups members into challenges: a member that begins with an auth-scheme
/// (token followed by whitespace or end-of-member) starts a new challenge; subsequent
/// members without a leading scheme are treated as continuation parameters for
/// the current challenge.
///
/// Returns Ok(Vec<String>) on success or Err(String) describing a parsing problem
/// (e.g., empty member, parameter before a scheme, or missing scheme on a member
/// that starts with whitespace).
pub fn split_and_group_challenges(s: &str) -> Result<Vec<String>, String> {
    let members: Vec<&str> = split_commas_respecting_quotes(s);
    let mut challenges: Vec<String> = Vec::new();

    for m in members {
        let mm = m.trim();
        if mm.is_empty() {
            return Err("WWW-Authenticate header contains empty challenge/member".into());
        }

        let is_new = {
            let s = mm;
            if let Some(idx) = s.find(char::is_whitespace) {
                let scheme = s[..idx].trim();
                crate::helpers::token::find_invalid_token_char(scheme).is_none()
            } else if s.contains('=') {
                false
            } else {
                crate::helpers::token::find_invalid_token_char(s).is_none()
            }
        };

        if is_new {
            challenges.push(mm.to_string());
        } else if let Some(last) = challenges.last_mut() {
            last.push_str(", ");
            last.push_str(mm);
        } else {
            // continuation without a starting challenge -> syntax issue
            if m.chars().next().map(|c| c.is_whitespace()).unwrap_or(false) {
                return Err("WWW-Authenticate challenge missing auth-scheme".into());
            }
            return Err("WWW-Authenticate contains parameter before any auth-scheme".into());
        }
    }

    Ok(challenges)
}

/// Validate a single assembled WWW-Authenticate challenge string.
/// Returns Ok(()) when syntactically acceptable, or Err(String) describing the problem.
pub fn validate_challenge_syntax(challenge: &str) -> Result<(), String> {
    let c = challenge.trim();
    if c.is_empty() {
        return Err("WWW-Authenticate header contains empty challenge".into());
    }

    // scheme is first token before whitespace
    let mut parts = c.splitn(2, char::is_whitespace);
    let scheme = parts.next().unwrap().trim();
    if scheme.is_empty() {
        return Err("WWW-Authenticate challenge missing auth-scheme".into());
    }
    if let Some(invalid) = crate::helpers::token::find_invalid_token_char(scheme) {
        return Err(format!(
            "Invalid character '{}' in WWW-Authenticate auth-scheme",
            invalid
        ));
    }

    if let Some(rest) = parts.next() {
        let rest = rest.trim();
        if rest.is_empty() {
            return Ok(());
        }

        if !rest.contains('=') {
            if rest.chars().any(|c| (c as u32) < 0x20 || c == '\x7f') {
                return Err("WWW-Authenticate token68 contains control characters".into());
            }
            if !rest
                .chars()
                .any(|ch| matches!(ch, '+' | '/' | '=' | '.' | '-' | '_'))
            {
                return Err(format!(
                    "WWW-Authenticate challenge has suspicious single token '{}' after scheme; token68 or auth-param expected",
                    rest
                ));
            }
            return Ok(());
        }

        // rest contains '='; decide heuristics
        let first_part = rest.split('=').next().unwrap_or("").trim();
        let after_eq = rest.split_once('=').map(|x| x.1).unwrap_or("").trim();
        let first_invalid = crate::helpers::token::find_invalid_token_char(first_part).is_some();
        if !rest.contains(',') {
            if first_invalid && !after_eq.starts_with('"') {
                if rest.chars().any(|c| (c as u32) < 0x20 || c == '\x7f') {
                    return Err("WWW-Authenticate token68 contains control characters".into());
                }
                return Ok(());
            }

            if rest.ends_with('=') && after_eq.is_empty() {
                if !scheme.eq_ignore_ascii_case("basic")
                    && !scheme.eq_ignore_ascii_case("bearer")
                    && !scheme.eq_ignore_ascii_case("digest")
                {
                    if rest.chars().any(|c| (c as u32) < 0x20 || c == '\x7f') {
                        return Err("WWW-Authenticate token68 contains control characters".into());
                    }
                    return Ok(());
                } else {
                    return Err(format!(
                        "WWW-Authenticate auth-param '{}' missing value",
                        first_part
                    ));
                }
            }
        }

        // Parse auth-params
        for param in split_commas_respecting_quotes(rest) {
            let param = param.trim();
            if param.is_empty() {
                return Err("WWW-Authenticate contains empty parameter".into());
            }
            let mut kv = param.splitn(2, '=');
            let name = kv.next().unwrap().trim();
            let val = kv.next();
            if name.is_empty() {
                return Err("WWW-Authenticate auth-param name is empty".into());
            }
            if val.is_none() {
                return Err(format!(
                    "WWW-Authenticate auth-param '{}' missing value",
                    name
                ));
            }
            if let Some(inv) = crate::helpers::token::find_invalid_token_char(name) {
                return Err(format!("Invalid character '{}' in auth-param name", inv));
            }
            let v = val.unwrap().trim();
            if v.is_empty() {
                return Err(format!(
                    "WWW-Authenticate auth-param '{}' missing value",
                    name
                ));
            }
            if v.starts_with('"') {
                if let Err(msg) = crate::helpers::headers::validate_quoted_string(v) {
                    return Err(format!(
                        "Invalid quoted-string in auth-param '{}': {}",
                        name, msg
                    ));
                }
            } else if let Some(inv) = crate::helpers::token::find_invalid_token_char(v) {
                return Err(format!("Invalid character '{}' in auth-param value", inv));
            }
        }
    }

    Ok(())
}

/// Validate an `Authorization` header value for having both a valid auth-scheme and
/// non-empty credentials (token68 or auth-param list). Unlike `WWW-Authenticate` challenges,
/// the `Authorization` header MUST include credentials after the auth-scheme.
/// Returns Ok(()) on success or Err(String) describing the problem.
pub fn validate_authorization_syntax(value: &str) -> Result<(), String> {
    let v = value.trim();
    if v.is_empty() {
        return Err("Authorization header is empty".into());
    }

    let mut parts = v.splitn(2, char::is_whitespace);
    let scheme = parts.next().unwrap().trim();
    if scheme.is_empty() {
        return Err("Authorization header missing auth-scheme".into());
    }
    if let Some(invalid) = crate::helpers::token::find_invalid_token_char(scheme) {
        return Err(format!(
            "Invalid character '{}' in Authorization auth-scheme",
            invalid
        ));
    }

    // Authorization MUST include credentials after scheme (unlike WWW-Authenticate)
    if let Some(rest) = parts.next() {
        let rest = rest.trim();
        if rest.is_empty() {
            return Err("Authorization header missing credentials after auth-scheme".into());
        }
        // Basic checks: no control characters
        if rest.chars().any(|c| (c as u32) < 0x20 || c == '\x7f') {
            return Err("Authorization credentials contain control characters".into());
        }
        Ok(())
    } else {
        Err("Authorization header missing credentials after auth-scheme".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_single_challenge() {
        let got = split_and_group_challenges("Basic realm=\"x\"").unwrap();
        assert_eq!(got, vec!["Basic realm=\"x\"".to_string()]);
    }

    #[test]
    fn validate_authorization_basic_ok() {
        assert!(validate_authorization_syntax("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==").is_ok());
    }

    #[test]
    fn validate_authorization_bearer_ok() {
        assert!(validate_authorization_syntax("Bearer abc123").is_ok());
    }

    #[test]
    fn validate_authorization_digest_ok() {
        assert!(
            validate_authorization_syntax("Digest username=\"Mufasa\", realm=\"test\"").is_ok()
        );
    }

    #[test]
    fn validate_authorization_missing_credentials() {
        assert!(validate_authorization_syntax("Basic").is_err());
        assert!(validate_authorization_syntax("Basic ").is_err());
    }

    #[test]
    fn validate_authorization_invalid_scheme_char() {
        assert!(validate_authorization_syntax("B@sic xyz").is_err());
    }

    #[test]
    fn validate_authorization_control_chars() {
        assert!(validate_authorization_syntax("Bearer \u{0001}").is_err());
    }

    #[test]
    fn multiple_members_grouped_into_challenge() {
        let got = split_and_group_challenges("Basic, realm=\"x\"").unwrap();
        assert_eq!(got, vec!["Basic, realm=\"x\"".to_string()]);
    }

    #[test]
    fn quoted_commas_are_respected() {
        let got = split_and_group_challenges("Basic realm=\"a,b\", more=1").unwrap();
        assert_eq!(got, vec!["Basic realm=\"a,b\", more=1".to_string()]);
    }

    #[test]
    fn multiple_challenges() {
        let got = split_and_group_challenges("Basic realm=\"a\", NewScheme abc=").unwrap();
        assert_eq!(
            got,
            vec![
                "Basic realm=\"a\"".to_string(),
                "NewScheme abc=".to_string()
            ]
        );
    }

    #[test]
    fn empty_member_is_error() {
        let r = split_and_group_challenges(", Basic realm=\"x\"");
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("empty"));
    }

    #[test]
    fn parameter_before_scheme_is_error() {
        let r = split_and_group_challenges("error=\"x\"");
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("parameter before any auth-scheme"));
    }

    #[test]
    fn member_starting_with_whitespace_reports_missing_scheme() {
        let r = split_and_group_challenges(" realm=\"x\"");
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("missing auth-scheme"));
    }

    #[test]
    fn consecutive_commas_report_error() {
        let r = split_and_group_challenges("Basic realm=\"x\", , error=\"y\"");
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("empty"));
    }

    #[test]
    fn validate_challenge_detects_missing_value_in_param_list() {
        let r = validate_challenge_syntax("Basic realm=\"x\", flag");
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("missing value"));
    }

    #[test]
    fn validate_empty_challenge() {
        let r = validate_challenge_syntax("");
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("empty challenge"));
    }

    #[test]
    fn validate_missing_scheme_error() {
        // Leading-space member would have been rejected earlier; here it becomes an invalid scheme
        let r = validate_challenge_syntax(" realm=\"x\"");
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("Invalid character"));
    }

    #[test]
    fn validate_invalid_scheme_char() {
        let r = validate_challenge_syntax("B@sic realm=\"x\"");
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("Invalid character"));
    }

    #[test]
    fn validate_scheme_only_ok() {
        let r = validate_challenge_syntax("Basic");
        assert!(r.is_ok());
    }

    #[test]
    fn suspicious_single_token_after_scheme_reports_error() {
        let r = validate_challenge_syntax("NewSch abcd");
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("suspicious single token"));
    }

    #[test]
    fn token68_with_control_character_reports_error() {
        let r = validate_challenge_syntax("NewSch \u{0001}");
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("control characters"));
    }

    #[test]
    fn first_part_invalid_and_after_eq_no_quotes_permitted_as_token68() {
        let r = validate_challenge_syntax("NewSch bad@=abc");
        assert!(r.is_ok());
    }

    #[test]
    fn scheme_with_trailing_eq_on_basic_reports_missing_value() {
        let r = validate_challenge_syntax("Basic realm=");
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("missing value"));
    }

    #[test]
    fn scheme_with_trailing_eq_on_non_basic_is_ok() {
        let r = validate_challenge_syntax("NewSch realm=");
        assert!(r.is_ok());
    }

    #[test]
    fn empty_parameter_in_param_list_is_error() {
        let r = validate_challenge_syntax("Basic realm=\"x\", ");
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("empty parameter"));
    }

    #[test]
    fn empty_param_name_is_error() {
        let r = validate_challenge_syntax("Basic =\"x\"");
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("auth-param name is empty"));
    }

    #[test]
    fn invalid_character_in_param_name_is_error() {
        let r = validate_challenge_syntax("Basic re@alm=1, x=1");
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("Invalid character"));
    }

    #[test]
    fn param_with_missing_value_in_params_is_error() {
        let r = validate_challenge_syntax("NewSch realm=, other=1");
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("missing value"));
    }

    #[test]
    fn invalid_quoted_string_in_param_reports_error() {
        let r = validate_challenge_syntax("Basic realm=\"unterminated");
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("Invalid quoted-string"));
    }

    #[test]
    fn invalid_character_in_param_value_is_error() {
        let r = validate_challenge_syntax("Basic realm=x@y");
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("Invalid character"));
    }

    #[test]
    fn token68_with_allowed_chars_ok() {
        let r = validate_challenge_syntax("NewSch abc+");
        assert!(r.is_ok());
    }
}
