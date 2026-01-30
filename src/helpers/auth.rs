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
    let scheme = parts
        .next()
        .expect("splitn always yields at least one element")
        .trim();
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
                }

                return Err(format!(
                    "WWW-Authenticate auth-param '{}' missing value",
                    first_part
                ));
            }
        }

        // Parse auth-params
        for param in split_commas_respecting_quotes(rest) {
            let param = param.trim();
            if param.is_empty() {
                return Err("WWW-Authenticate contains empty parameter".into());
            }
            let mut kv = param.splitn(2, '=');
            let name = kv
                .next()
                .expect("splitn always yields at least one element")
                .trim();
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
            let v = val.expect("checked for none above").trim();
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
use base64::Engine;

pub fn validate_authorization_syntax(value: &str) -> Result<(), String> {
    let v = value.trim();
    if v.is_empty() {
        return Err("Authorization header is empty".into());
    }

    let mut parts = v.splitn(2, char::is_whitespace);
    let scheme = parts
        .next()
        .expect("splitn always yields at least one element")
        .trim();
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

/// Validate Basic auth credentials token68 (base64 encoding of user-pass octet string).
/// Returns Ok(()) on syntactically valid Basic credentials, or Err(String) describing the problem.
///
/// Validation performed:
/// - Base64 decodes successfully
/// - Decoded octets contain at least one ':' separator
/// - User-id (octets before first ':') does not contain control characters
/// - Password (octets after first ':') does not contain control characters
pub fn validate_basic_credentials(token68: &str) -> Result<(), String> {
    let s = token68.trim();
    if s.is_empty() {
        return Err("Basic credentials token is empty".into());
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| format!("Invalid base64 in Basic credentials: {}", e))?;
    if decoded.is_empty() {
        return Err("Decoded Basic credentials empty".into());
    }
    // find first colon separator
    let pos = decoded.iter().position(|b| *b == b':');
    if pos.is_none() {
        return Err("Decoded Basic credentials missing ':' separator".into());
    }
    let pos = pos.expect("checked for none above");
    let (user, pass) = decoded.split_at(pos);
    // pass starts with ':' character; skip it
    let pass = &pass[1..];

    let contains_ctl =
        |bytes: &[u8]| -> Option<u8> { bytes.iter().find(|&&b| b < 0x20 || b == 0x7f).copied() };

    if let Some(v) = contains_ctl(user) {
        return Err(format!("User-id contains control character: 0x{:02x}", v));
    }
    if let Some(v) = contains_ctl(pass) {
        return Err(format!("Password contains control character: 0x{:02x}", v));
    }

    Ok(())
}
/// Validate Bearer token per token68-like rules: token must be non-empty, contain no
/// whitespace, the main body may contain only ALPHA / DIGIT / '-' / '.' / '_' / '~' / '+' / '/'
/// and any trailing padding must be '=' characters. Returns Ok(()) or Err(String).
pub fn validate_bearer_token(token: &str) -> Result<(), String> {
    let s = token.trim();
    if s.is_empty() {
        return Err("Bearer token is empty".into());
    }

    // No whitespace anywhere
    if s.chars().any(|c| c.is_ascii_whitespace()) {
        return Err("Bearer token contains whitespace".into());
    }

    // Split at first '=' to identify padding (if any)
    let first_eq = s.find('=');
    let (main, padding) = match first_eq {
        Some(idx) => (&s[..idx], &s[idx..]),
        None => (s, ""),
    };

    if main.is_empty() {
        return Err("Bearer token has empty main part".into());
    }

    let allowed_main =
        |c: char| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~' | '+' | '/');

    for c in main.chars() {
        if !allowed_main(c) {
            return Err(format!("Invalid character '{}' in Bearer token", c));
        }
    }

    for c in padding.chars() {
        if c != '=' {
            return Err("Bearer token padding contains invalid character".into());
        }
    }

    Ok(())
}

/// Parse an auth-param list (e.g., `username="Mufasa", realm="x", nonce=abc`) into a
/// HashMap of (name -> value) pairs. Values preserve quotes when present (e.g., `"x"`).
/// Returns Err(String) on parse error.
pub fn parse_auth_params(s: &str) -> Result<std::collections::HashMap<String, String>, String> {
    let mut out = std::collections::HashMap::new();
    // split comma-separated params respecting quoted-strings
    for part in split_commas_respecting_quotes(s) {
        let p = part.trim();
        if p.is_empty() {
            return Err("empty auth-param".into());
        }
        let mut kv = p.splitn(2, '=');
        let name = kv
            .next()
            .map(|x| x.trim())
            .filter(|x| !x.is_empty())
            .ok_or_else(|| "empty auth-param name".to_string())?;
        let val = kv
            .next()
            .map(|x| x.trim())
            .ok_or_else(|| format!("auth-param '{}' missing value", name))?;
        // name must be a token
        if let Some(inv) = crate::helpers::token::find_invalid_token_char(name) {
            return Err(format!("Invalid character '{}' in auth-param name", inv));
        }
        out.insert(name.to_ascii_lowercase(), val.to_string());
    }
    Ok(out)
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
    fn validate_authorization_digest_missing_credentials() {
        assert!(validate_authorization_syntax("Digest").is_err());
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
    fn parse_auth_params_ok_and_lowercases_names() {
        let got = parse_auth_params("username=\"Mufasa\", realm=\"x\", nonce=abc").unwrap();
        assert_eq!(got.get("username").map(|s| s.as_str()), Some("\"Mufasa\""));
        assert_eq!(got.get("realm").map(|s| s.as_str()), Some("\"x\""));
        assert_eq!(got.get("nonce").map(|s| s.as_str()), Some("abc"));
    }

    #[test]
    fn parse_auth_params_errors_on_missing_value_or_name() {
        assert!(parse_auth_params("username").is_err());
        assert!(parse_auth_params("=abc").is_err());
        assert!(parse_auth_params("").is_err());
    }

    #[test]
    fn parse_auth_params_invalid_name_char() {
        let r = parse_auth_params("user@name=abc");
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("Invalid character"));
    }

    #[test]
    fn parse_auth_params_empty_member_is_error() {
        let r = parse_auth_params("a=b, , c=d");
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("empty"));
    }

    #[test]
    fn parse_auth_params_trailing_comma_is_error() {
        let r = parse_auth_params("a=b,");
        assert!(r.is_err());
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

    // Tests for validate_bearer_token helper
    #[test]
    fn validate_bearer_token_ok_and_padding() {
        assert!(validate_bearer_token("abc123").is_ok());
        assert!(validate_bearer_token("abc+").is_ok());
        assert!(validate_bearer_token("abc==").is_ok());
    }

    #[test]
    fn validate_bearer_token_rejects_whitespace_and_invalid_chars() {
        assert!(validate_bearer_token("a b").is_err());
        assert!(validate_bearer_token("").is_err());
        assert!(validate_bearer_token("a@b").is_err());
    }

    #[test]
    fn validate_bearer_token_rejects_eq_in_middle_or_nonpad() {
        assert!(validate_bearer_token("ab=c").is_err());
        assert!(validate_bearer_token("ab=c==").is_err());
        assert!(validate_bearer_token("=abc").is_err());
        assert!(validate_bearer_token("abc=a").is_err());
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
    fn validate_basic_credentials_ok() {
        // 'Aladdin:open sesame' -> base64
        assert!(validate_basic_credentials("QWxhZGRpbjpvcGVuIHNlc2FtZQ==").is_ok());
    }

    #[test]
    fn validate_basic_credentials_missing_colon() {
        // 'abc' base64
        assert!(validate_basic_credentials("YWJj").is_err());
    }

    #[test]
    fn validate_basic_credentials_invalid_base64() {
        assert!(validate_basic_credentials("not-base64!!").is_err());
    }

    #[test]
    fn validate_basic_credentials_ctl_in_password() {
        // user:pass where pass contains 0x01
        let creds = b"user:\x01pass";
        let enc = base64::engine::general_purpose::STANDARD.encode(creds);
        let res = validate_basic_credentials(&enc);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("control"));
    }

    #[test]
    fn validate_basic_credentials_ctl_in_user() {
        // user contains 0x01
        let creds = b"us\x01er:pass";
        let enc = base64::engine::general_purpose::STANDARD.encode(creds);
        let res = validate_basic_credentials(&enc);
        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .contains("User-id contains control character"));
    }

    #[test]
    fn validate_basic_credentials_empty_token() {
        assert!(validate_basic_credentials("").is_err());
    }
    #[test]
    fn validate_basic_credentials_empty_user_allowed() {
        // ':pass' should be allowed (empty user-id) as long as no control chars
        let creds = b":pass";
        let enc = base64::engine::general_purpose::STANDARD.encode(creds);
        assert!(validate_basic_credentials(&enc).is_ok());
    }

    #[test]
    fn invalid_quoted_string_in_param_reports_error() {
        let r = validate_challenge_syntax("Basic realm=\"unterminated");
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("Invalid quoted-string"));
    }

    #[test]
    fn quoted_string_ends_with_escape_reports_error() {
        // Build the string programmatically to ensure exact control of contents:
        // Resulting string contains the characters: '"' 'a' 'b' 'c' '\' '"' i.e. "abc\"
        let mut s = String::new();
        s.push('"');
        s.push_str("abc");
        s.push('\\');
        s.push('"');
        let r = crate::helpers::headers::validate_quoted_string(&s);
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("ends with escape"));
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
