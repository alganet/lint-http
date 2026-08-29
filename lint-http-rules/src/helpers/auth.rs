// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::helpers::list::split_commas_respecting_quotes;

/// Split a WWW-Authenticate header value into "assembled" challenges.
///
/// This function splits top-level comma-separated members (respecting quoted-strings)
/// and groups members into challenges: a member that begins with an auth-scheme
/// (token followed by whitespace or end-of-member) starts a new challenge; subsequent
/// members without a leading scheme are treated as continuation parameters for
/// the current challenge.
///
/// Returns `Ok(Vec<String>)` on success or `Err(String)` describing a parsing
/// problem: an empty member, or a parameter with no challenge before it. There
/// was a third — *missing scheme on a member that starts with whitespace* — and
/// it was the same problem read off a character the list grammar puts outside
/// the element.
pub fn split_and_group_challenges(s: &str) -> Result<Vec<String>, String> {
    let members: Vec<&str> = split_commas_respecting_quotes(s);
    let mut challenges: Vec<String> = Vec::new();

    for m in members {
        // The `OWS` the `#rule` prints around its commas is the splitter's to
        // remove, and it removes exactly that — the `str::trim` this replaced
        // also took %xA0 and %x85 off a member's ends, which are `obs-text` and
        // are two of the octets the `auth-scheme` check below exists to name.
        let mm = m;
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
            // A continuation with no challenge before it. There used to be two
            // messages here, chosen by whether the member as split began with
            // whitespace — and that was the `OWS` of `#challenge`'s own comma
            // separator being read as evidence about the challenge. ` realm="x"`
            // and `realm="x"` are the same member: §5.6.1.1 puts the whitespace
            // outside the element, so after it is removed there is one case and
            // one thing to say about it.
            // cite(RFC 9110 § 11.6.1): "WWW-Authenticate = #challenge"
            // cite(RFC 9110 § 5.6.1.1): "1#element => element *( OWS "," OWS element )"
            return Err("WWW-Authenticate contains parameter before any auth-scheme".into());
        }
    }

    Ok(challenges)
}

/// What a single assembled `WWW-Authenticate` challenge fails to be.
///
/// The split is by *what was being read*, which is the only way these group:
/// the challenge as a whole, the `auth-scheme`, the `token68` alternative, and
/// the `#auth-param` one. Two variants that look alike belong to different
/// halves of that — [`SchemeCharacter`](Self::SchemeCharacter) and
/// [`ParameterNameCharacter`](Self::ParameterNameCharacter) both report a
/// non-`token` octet, and the production each read it under is the difference.
///
/// [`SuspiciousSingleToken`](Self::SuspiciousSingleToken) is the one variant
/// that is not a grammar failure and says so in its name. `token68` admits a
/// bare word, so `NewSch abcd` is well-formed by § 11.2; what this reports is
/// that it is *indistinguishable* from an `auth-param` someone forgot the value
/// of. Naming it keeps that heuristic from reading as a syntax verdict — the
/// `String` this replaced made it one sentence among the rest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeDefect<'a> {
    /// Nothing between the commas the challenge was assembled from.
    Empty,
    /// A non-`token` octet in the `auth-scheme`, carrying the character.
    SchemeCharacter(char),
    /// A control octet where a `token68` was read. `token68`'s alphabet is
    /// ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" and its padding, and a
    /// control octet is in none of it.
    Token68ControlCharacter,
    /// A single bare word after the scheme that is a `token68` by the grammar
    /// and a value-less `auth-param` by eye. Carries the word.
    SuspiciousSingleToken(&'a str),
    /// An empty member of the `#auth-param` list.
    EmptyParameter,
    /// A member whose name is empty — `=x`, which has a value and nothing it
    /// belongs to.
    EmptyParameterName,
    /// An `auth-param` with no value, carrying the name. `auth-param` is
    /// `token BWS "=" BWS ( token / quoted-string )`: the value is not optional.
    ParameterMissingValue(&'a str),
    /// A non-`token` octet in an `auth-param` name, carrying the character.
    ParameterNameCharacter(char),
    /// A non-`token` octet in an unquoted `auth-param` value, carrying the
    /// character.
    ParameterValueCharacter(char),
    /// A value that opens with a DQUOTE and is not a well-formed
    /// `quoted-string`. Carries the parameter it belonged to, the value as
    /// written, and the [`QuotedStringDefect`](crate::helpers::quoted_string::QuotedStringDefect) — the reason this
    /// conversion needed the typed answer from that module, since the finding
    /// names the parameter and the defect names the value.
    ParameterQuotedValue {
        /// The `auth-param` name the bad value belonged to.
        name: &'a str,
        /// The value as written, DQUOTEs included.
        value: &'a str,
        /// What it failed to be.
        defect: crate::helpers::quoted_string::QuotedStringDefect,
    },
}

impl ChallengeDefect<'_> {
    /// The finding. Every sentence names `WWW-Authenticate` or the production
    /// inside it, because this helper serves one field and its callers embed
    /// the sentence whole.
    pub fn message(self) -> String {
        match self {
            Self::Empty => "WWW-Authenticate header contains empty challenge".to_string(),
            Self::SchemeCharacter(c) => {
                format!("Invalid character '{}' in WWW-Authenticate auth-scheme", c)
            }
            Self::Token68ControlCharacter => {
                "WWW-Authenticate token68 contains control characters".to_string()
            }
            Self::SuspiciousSingleToken(word) => format!(
                "WWW-Authenticate challenge has suspicious single token '{}' after scheme; token68 or auth-param expected",
                word
            ),
            Self::EmptyParameter => "WWW-Authenticate contains empty parameter".to_string(),
            Self::EmptyParameterName => "WWW-Authenticate auth-param name is empty".to_string(),
            Self::ParameterMissingValue(name) => {
                format!("WWW-Authenticate auth-param '{}' missing value", name)
            }
            Self::ParameterNameCharacter(c) => {
                format!("Invalid character '{}' in auth-param name", c)
            }
            Self::ParameterValueCharacter(c) => {
                format!("Invalid character '{}' in auth-param value", c)
            }
            Self::ParameterQuotedValue {
                name,
                value,
                defect,
            } => format!(
                "Invalid quoted-string in auth-param '{}': {}",
                name,
                defect.message(value)
            ),
        }
    }
}

/// Whether one assembled `WWW-Authenticate` challenge is syntactically
/// acceptable, answered as a [`ChallengeDefect`].
///
/// **A challenge cannot fail to have an `auth-scheme` here, and the branch that
/// said it could is gone.** The value is trimmed and checked for emptiness
/// first, so it opens with a non-whitespace character; the scheme is everything
/// before the first `char::is_whitespace`, which is therefore non-empty, and
/// `str::trim` removes exactly that same set so it cannot empty it either. The
/// old `"challenge missing auth-scheme"` string was unreachable, and only became
/// visible when the failures had to be enumerated as variants — an enum with a
/// variant nothing constructs is a claim the module cannot back. What the test
/// named `validate_missing_scheme_error` actually exercises is a leading-space
/// member whose scheme reads as `realm="x"` and fails on the `=`.
pub fn validate_challenge_syntax(challenge: &str) -> Result<(), ChallengeDefect<'_>> {
    let c = challenge.trim();
    if c.is_empty() {
        return Err(ChallengeDefect::Empty);
    }

    // The three `token68` readings below share this: the alternative's alphabet
    // has no control octet in it, whichever way the value reached the branch.
    let has_control = |s: &str| s.chars().any(|c| (c as u32) < 0x20 || c == '\x7f');

    // scheme is first token before whitespace
    // cite(RFC 9110 § 11.3): "challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]"
    let mut parts = c.splitn(2, char::is_whitespace);
    let scheme = parts
        .next()
        .expect("splitn always yields at least one element")
        .trim();
    if let Some(invalid) = crate::helpers::token::find_invalid_token_char(scheme) {
        return Err(ChallengeDefect::SchemeCharacter(invalid));
    }

    if let Some(rest) = parts.next() {
        let rest = rest.trim();
        if rest.is_empty() {
            return Ok(());
        }

        if !rest.contains('=') {
            if has_control(rest) {
                return Err(ChallengeDefect::Token68ControlCharacter);
            }
            if !rest
                .chars()
                .any(|ch| matches!(ch, '+' | '/' | '=' | '.' | '-' | '_'))
            {
                return Err(ChallengeDefect::SuspiciousSingleToken(rest));
            }
            return Ok(());
        }

        // rest contains '='; decide heuristics
        let first_part = rest.split('=').next().unwrap_or("").trim();
        let after_eq = rest.split_once('=').map(|x| x.1).unwrap_or("").trim();
        let first_invalid = crate::helpers::token::find_invalid_token_char(first_part).is_some();
        if !rest.contains(',') {
            if first_invalid && !after_eq.starts_with('"') {
                if has_control(rest) {
                    return Err(ChallengeDefect::Token68ControlCharacter);
                }
                return Ok(());
            }

            if rest.ends_with('=') && after_eq.is_empty() {
                if !scheme.eq_ignore_ascii_case("basic")
                    && !scheme.eq_ignore_ascii_case("bearer")
                    && !scheme.eq_ignore_ascii_case("digest")
                {
                    if has_control(rest) {
                        return Err(ChallengeDefect::Token68ControlCharacter);
                    }
                    return Ok(());
                }

                return Err(ChallengeDefect::ParameterMissingValue(first_part));
            }
        }

        // Parse auth-params. The `OWS` around the `#auth-param` commas is the
        // splitter's; the `str::trim` this replaced also took the two `obs-text`
        // octets that look like whitespace, and no `token` admits either.
        for param in split_commas_respecting_quotes(rest) {
            if param.is_empty() {
                return Err(ChallengeDefect::EmptyParameter);
            }
            let mut kv = param.splitn(2, '=');
            let name = kv
                .next()
                .expect("splitn always yields at least one element")
                .trim();
            let val = kv.next();
            if name.is_empty() {
                return Err(ChallengeDefect::EmptyParameterName);
            }
            let Some(val) = val else {
                return Err(ChallengeDefect::ParameterMissingValue(name));
            };
            if let Some(inv) = crate::helpers::token::find_invalid_token_char(name) {
                return Err(ChallengeDefect::ParameterNameCharacter(inv));
            }
            let v = val.trim();
            if v.is_empty() {
                return Err(ChallengeDefect::ParameterMissingValue(name));
            }
            if v.starts_with('"') {
                if let Err(defect) = crate::helpers::quoted_string::check_quoted_string(v) {
                    return Err(ChallengeDefect::ParameterQuotedValue {
                        name,
                        value: v,
                        defect,
                    });
                }
            } else if let Some(inv) = crate::helpers::token::find_invalid_token_char(v) {
                return Err(ChallengeDefect::ParameterValueCharacter(inv));
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
    // cite(RFC 9110 § 11.1): "It uses a case-insensitive token to identify the authentication scheme"
    if let Some(invalid) = crate::helpers::token::find_invalid_token_char(scheme) {
        return Err(format!(
            "Invalid character '{}' in Authorization auth-scheme",
            invalid
        ));
    }

    // §11.4's grammar makes the part after the scheme optional ([ 1*SP … ]), so a
    // bare scheme is framework-valid. This helper still requires something there
    // because every concrete scheme it serves — Basic (RFC 7617), Bearer (RFC 6750),
    // Digest (RFC 7616) — mandates credentials, so a scheme with nothing after it is
    // treated as malformed. The cite anchors the structure (scheme, then optional
    // credentials), not the requirement, which is scheme-derived and stricter than
    // the framework grammar.
    // cite(RFC 9110 § 11.4): "credentials = auth-scheme [ 1*SP ( token68 / #auth-param ) ]"
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

/// What `Basic` credentials fail to be.
///
/// The split follows the two layers RFC 7617 stacks: the `token68` is base64,
/// and what it decodes to is a `user-pass`. [`Empty`](Self::Empty) and
/// [`Base64`](Self::Base64) are the outer one, the other three the inner —
/// which is the distinction a reader needs, because a defect in the inner layer
/// says the sender encoded something well and chose it badly.
///
/// This one is `Clone` rather than `Copy`, alone among the defect enums here,
/// and [`Base64`](Self::Base64) is why: `base64::DecodeError` names the
/// offending symbol and its offset, which is worth carrying and is not `Copy`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BasicCredentialsDefect {
    /// No `token68` at all.
    Empty,
    /// Not base64. Carries the decoder's own account of where it stopped —
    /// rejecting a malformed encoding is RFC 4648's instruction rather than
    /// strictness for its own sake.
    Base64(base64::DecodeError),
    /// Decoded octets with no `:` in them. Without the separator there is no
    /// telling where the user-id stops, and `user-id` may itself be empty —
    /// which is a different thing from absent.
    MissingColon,
    /// A control octet in the user-id, carrying it.
    UserIdControlCharacter(u8),
    /// A control octet in the password, carrying it.
    PasswordControlCharacter(u8),
}

impl BasicCredentialsDefect {
    /// The finding. The `0x` spelling is deliberate for the two control-octet
    /// variants: the octet is by definition one that would not survive being
    /// printed into the sentence reporting it.
    pub fn message(self) -> String {
        match self {
            Self::Empty => "Basic credentials token is empty".to_string(),
            Self::Base64(e) => format!("Invalid base64 in Basic credentials: {}", e),
            Self::MissingColon => "Decoded Basic credentials missing ':' separator".to_string(),
            Self::UserIdControlCharacter(b) => {
                format!("User-id contains control character: 0x{:02x}", b)
            }
            Self::PasswordControlCharacter(b) => {
                format!("Password contains control character: 0x{:02x}", b)
            }
        }
    }
}

/// Whether a `Basic` `token68` is well-formed credentials, answered as a
/// [`BasicCredentialsDefect`].
///
/// Validation performed:
/// - Base64 decodes successfully
/// - Decoded octets contain at least one ':' separator
/// - User-id (octets before first ':') does not contain control characters
/// - Password (octets after first ':') does not contain control characters
///
/// **A successful decode here is never empty, and the guard that said otherwise
/// is gone.** Zero octets come out of zero base64 symbols; the value is trimmed
/// and rejected for emptiness above, so there is at least one symbol, and one
/// alone is `InvalidLength`. `"Decoded Basic credentials empty"` was a sentence
/// no input produced. If the decoder ever did return nothing for something, the
/// next line reports a `user-pass` with no `:` in it — which is what it would
/// be.
pub fn validate_basic_credentials(token68: &str) -> Result<(), BasicCredentialsDefect> {
    let s = token68.trim();
    if s.is_empty() {
        return Err(BasicCredentialsDefect::Empty);
    }
    // cite(RFC 7617 § 2, label: basic-credentials base64): "and obtains the basic-credentials by encoding this octet sequence using Base64"
    // Erroring out on a malformed encoding is RFC 4648's own instruction, not
    // strictness for its own sake — and RFC 7617 does not state otherwise.
    // cite(RFC 4648 § 3.3, label: base64 rejects non-alphabet): "Implementations MUST reject the encoded data if it contains characters outside the base alphabet when interpreting base-encoded data, unless the specification referring to this document explicitly states otherwise."
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(BasicCredentialsDefect::Base64)?;
    // find first colon separator
    // cite(RFC 7617 § 2): "constructs the user-pass by concatenating the user-id, a single colon (":") character, and the password"
    let Some(pos) = decoded.iter().position(|b| *b == b':') else {
        return Err(BasicCredentialsDefect::MissingColon);
    };
    let (user, pass) = decoded.split_at(pos);
    // pass starts with ':' character; skip it
    let pass = &pass[1..];

    // cite(RFC 7617 § 2): "The user-id and password MUST NOT contain any control characters"
    let contains_ctl =
        |bytes: &[u8]| -> Option<u8> { bytes.iter().find(|&&b| b < 0x20 || b == 0x7f).copied() };

    if let Some(v) = contains_ctl(user) {
        return Err(BasicCredentialsDefect::UserIdControlCharacter(v));
    }
    if let Some(v) = contains_ctl(pass) {
        return Err(BasicCredentialsDefect::PasswordControlCharacter(v));
    }

    Ok(())
}

/// What a `Bearer` token fails to be.
///
/// All five are the one production, `b64token`, read in the order its ABNF
/// writes it: something, then the body's alphabet, then the padding.
/// [`Whitespace`](Self::Whitespace) is separated from
/// [`BadCharacter`](Self::BadCharacter) although a space is just another
/// character outside the set, because a token with a space in it is usually two
/// things where one was expected rather than one thing misspelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BearerTokenDefect {
    /// No token.
    Empty,
    /// Whitespace anywhere in the token.
    Whitespace,
    /// Padding and nothing before it. `b64token` is `1*(...)` and then its
    /// `*"="`, so the body cannot be the empty string.
    EmptyBody,
    /// An octet outside `b64token`'s body alphabet, carrying the character.
    BadCharacter(char),
    /// Something other than `=` at or after the first `=`. Padding is the only
    /// thing that may follow the body, so a `=` in the middle makes everything
    /// after it padding by position.
    BadPadding,
}

impl BearerTokenDefect {
    /// The finding. Each names `Bearer`, because a caller has one field's worth
    /// of context to add and this helper serves one scheme.
    pub fn message(self) -> String {
        match self {
            Self::Empty => "Bearer token is empty".to_string(),
            Self::Whitespace => "Bearer token contains whitespace".to_string(),
            Self::EmptyBody => "Bearer token has empty main part".to_string(),
            Self::BadCharacter(c) => format!("Invalid character '{}' in Bearer token", c),
            Self::BadPadding => "Bearer token padding contains invalid character".to_string(),
        }
    }
}

/// Validate Bearer token per token68-like rules: token must be non-empty, contain no
/// whitespace, the main body may contain only ALPHA / DIGIT / '-' / '.' / '_' / '~' / '+' / '/'
/// and any trailing padding must be '=' characters, answered as a
/// [`BearerTokenDefect`].
pub fn validate_bearer_token(token: &str) -> Result<(), BearerTokenDefect> {
    let s = token.trim();
    if s.is_empty() {
        return Err(BearerTokenDefect::Empty);
    }

    // No whitespace anywhere
    if s.chars().any(|c| c.is_ascii_whitespace()) {
        return Err(BearerTokenDefect::Whitespace);
    }

    // Split at first '=' to identify padding (if any)
    let first_eq = s.find('=');
    let (main, padding) = match first_eq {
        Some(idx) => (&s[..idx], &s[idx..]),
        None => (s, ""),
    };

    if main.is_empty() {
        return Err(BearerTokenDefect::EmptyBody);
    }

    // cite(RFC 6750 § 2.1, label: bearer b64token grammar): "b64token    = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"=""
    let allowed_main =
        |c: char| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~' | '+' | '/');

    for c in main.chars() {
        if !allowed_main(c) {
            return Err(BearerTokenDefect::BadCharacter(c));
        }
    }

    for c in padding.chars() {
        if c != '=' {
            return Err(BearerTokenDefect::BadPadding);
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
        let p = part;
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

/// Parse the hexadecimal nonce-count value (`nc` auth-param).
///
/// The specification requires exactly eight hex digits, so we enforce that here
/// and convert to a `u64` for easy comparison.  The returned error string is
/// suitable for inclusion in violation messages.
pub fn parse_nc_hex(s: &str) -> Result<u64, String> {
    let s = s.trim();
    // RFC 7616 gives `nc` no ABNF at all. § 3.4 introduces it as "the hexadecimal
    // count" and never fixes its width; the sentence below is the only place in the
    // document that does. It sits in § 3.5, about Authentication-Info, but the same
    // section requires that field's nc to be the one from the client's request — so
    // it is one value with one width, and this is where the width is written down.
    // cite(RFC 7616 § 3.5): "For historical reasons, the nc value MUST be exactly 8 hexadecimal digits."
    if s.len() != 8 {
        return Err("nc must be exactly 8 hex digits".into());
    }
    u64::from_str_radix(s, 16).map_err(|e| format!("invalid hex nc: {}", e))
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
    fn parse_nc_hex_valid() {
        assert_eq!(parse_nc_hex("00000001").unwrap(), 1);
        assert_eq!(parse_nc_hex("0000000a").unwrap(), 10);
        assert_eq!(parse_nc_hex("ffffffff").unwrap(), 0xffffffff);
    }

    #[test]
    fn parse_nc_hex_errors() {
        assert!(parse_nc_hex("1").is_err());
        assert!(parse_nc_hex("0000000g").is_err());
        assert!(parse_nc_hex("00000").is_err());
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

    /// The leading space is `#challenge`'s own `OWS`, so this member is the one
    /// above with whitespace in front of it and draws the same message. It used
    /// to draw a different one, chosen by a character the list grammar puts
    /// outside the element.
    #[test]
    fn a_members_leading_ows_does_not_change_what_it_is() {
        for value in [" realm=\"x\"", "\trealm=\"x\"", "realm=\"x\"  "] {
            let r = split_and_group_challenges(value);
            assert!(
                r.as_ref()
                    .is_err_and(|e| e.contains("parameter before any auth-scheme")),
                "{value}: {r:?}"
            );
        }
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
        assert_eq!(
            validate_challenge_syntax("Basic realm=\"x\", flag"),
            Err(ChallengeDefect::ParameterMissingValue("flag"))
        );
    }

    #[test]
    fn validate_empty_challenge() {
        assert_eq!(validate_challenge_syntax(""), Err(ChallengeDefect::Empty));
    }

    /// The name is what the challenge *cannot* fail at. A member with leading
    /// `OWS` has already been trimmed by the time it gets here, so what this
    /// reads as the `auth-scheme` is `realm="x"` and the `=` is what it reports
    /// — never a missing scheme, which no input reaches.
    #[test]
    fn validate_missing_scheme_error() {
        assert_eq!(
            validate_challenge_syntax(" realm=\"x\""),
            Err(ChallengeDefect::SchemeCharacter('='))
        );
    }

    #[test]
    fn validate_invalid_scheme_char() {
        assert_eq!(
            validate_challenge_syntax("B@sic realm=\"x\""),
            Err(ChallengeDefect::SchemeCharacter('@'))
        );
    }

    #[test]
    fn validate_scheme_only_ok() {
        let r = validate_challenge_syntax("Basic");
        assert!(r.is_ok());
    }

    #[test]
    fn suspicious_single_token_after_scheme_reports_error() {
        assert_eq!(
            validate_challenge_syntax("NewSch abcd"),
            Err(ChallengeDefect::SuspiciousSingleToken("abcd"))
        );
    }

    #[test]
    fn token68_with_control_character_reports_error() {
        assert_eq!(
            validate_challenge_syntax("NewSch \u{0001}"),
            Err(ChallengeDefect::Token68ControlCharacter)
        );
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
        assert_eq!(
            validate_bearer_token("a b"),
            Err(BearerTokenDefect::Whitespace)
        );
        assert_eq!(validate_bearer_token(""), Err(BearerTokenDefect::Empty));
        assert_eq!(
            validate_bearer_token("a@b"),
            Err(BearerTokenDefect::BadCharacter('@'))
        );
    }

    /// The four values here fail two different ways, which is what `is_err()`
    /// could not say. Everything from the first `=` is padding *by position*,
    /// so `ab=c` has well-formed body `ab` and padding `=c`; `=abc` has no body
    /// at all, and the padding it does have is never reached.
    #[test]
    fn validate_bearer_token_rejects_eq_in_middle_or_nonpad() {
        assert_eq!(
            validate_bearer_token("ab=c"),
            Err(BearerTokenDefect::BadPadding)
        );
        assert_eq!(
            validate_bearer_token("ab=c=="),
            Err(BearerTokenDefect::BadPadding)
        );
        assert_eq!(
            validate_bearer_token("=abc"),
            Err(BearerTokenDefect::EmptyBody)
        );
        assert_eq!(
            validate_bearer_token("abc=a"),
            Err(BearerTokenDefect::BadPadding)
        );
    }

    #[test]
    fn scheme_with_trailing_eq_on_basic_reports_missing_value() {
        assert_eq!(
            validate_challenge_syntax("Basic realm="),
            Err(ChallengeDefect::ParameterMissingValue("realm"))
        );
    }

    #[test]
    fn scheme_with_trailing_eq_on_non_basic_is_ok() {
        let r = validate_challenge_syntax("NewSch realm=");
        assert!(r.is_ok());
    }

    #[test]
    fn empty_parameter_in_param_list_is_error() {
        assert_eq!(
            validate_challenge_syntax("Basic realm=\"x\", "),
            Err(ChallengeDefect::EmptyParameter)
        );
    }

    #[test]
    fn empty_param_name_is_error() {
        assert_eq!(
            validate_challenge_syntax("Basic =\"x\""),
            Err(ChallengeDefect::EmptyParameterName)
        );
    }

    #[test]
    fn invalid_character_in_param_name_is_error() {
        assert_eq!(
            validate_challenge_syntax("Basic re@alm=1, x=1"),
            Err(ChallengeDefect::ParameterNameCharacter('@'))
        );
    }

    #[test]
    fn param_with_missing_value_in_params_is_error() {
        assert_eq!(
            validate_challenge_syntax("NewSch realm=, other=1"),
            Err(ChallengeDefect::ParameterMissingValue("realm"))
        );
    }

    #[test]
    fn validate_basic_credentials_ok() {
        // 'Aladdin:open sesame' -> base64
        assert!(validate_basic_credentials("QWxhZGRpbjpvcGVuIHNlc2FtZQ==").is_ok());
    }

    #[test]
    fn validate_basic_credentials_missing_colon() {
        // 'abc' base64
        assert_eq!(
            validate_basic_credentials("YWJj"),
            Err(BasicCredentialsDefect::MissingColon)
        );
    }

    /// The two layers, one after the other: `not-base64!!` never becomes a
    /// `user-pass` to have anything wrong with, and the decoder says where it
    /// stopped. An empty encoding decodes fine and is the other thing.
    #[test]
    fn validate_basic_credentials_invalid_base64() {
        assert_eq!(
            validate_basic_credentials("not-base64!!"),
            Err(BasicCredentialsDefect::Base64(
                base64::DecodeError::InvalidByte(3, b'-')
            ))
        );
        assert_eq!(
            validate_basic_credentials("===="),
            Err(BasicCredentialsDefect::Base64(
                base64::DecodeError::InvalidByte(0, b'=')
            ))
        );
    }

    #[test]
    fn validate_basic_credentials_ctl_in_password() {
        // user:pass where pass contains 0x01
        let creds = b"user:\x01pass";
        let enc = base64::engine::general_purpose::STANDARD.encode(creds);
        assert_eq!(
            validate_basic_credentials(&enc),
            Err(BasicCredentialsDefect::PasswordControlCharacter(0x01))
        );
    }

    #[test]
    fn validate_basic_credentials_ctl_in_user() {
        // user contains 0x01
        let creds = b"us\x01er:pass";
        let enc = base64::engine::general_purpose::STANDARD.encode(creds);
        assert_eq!(
            validate_basic_credentials(&enc),
            Err(BasicCredentialsDefect::UserIdControlCharacter(0x01))
        );
    }

    #[test]
    fn validate_basic_credentials_empty_token() {
        assert_eq!(
            validate_basic_credentials(""),
            Err(BasicCredentialsDefect::Empty)
        );
    }
    #[test]
    fn validate_basic_credentials_empty_user_allowed() {
        // ':pass' should be allowed (empty user-id) as long as no control chars
        let creds = b":pass";
        let enc = base64::engine::general_purpose::STANDARD.encode(creds);
        assert!(validate_basic_credentials(&enc).is_ok());
    }

    /// The finding names the parameter *and* the defect, which is the pair a
    /// `String` could only carry pre-spliced. `NotQuoted` is the variant: the
    /// value opens with a DQUOTE and nothing closes it, so there is no interior
    /// to have a defect in.
    #[test]
    fn invalid_quoted_string_in_param_reports_error() {
        let r = validate_challenge_syntax("Basic realm=\"unterminated");
        assert_eq!(
            r,
            Err(ChallengeDefect::ParameterQuotedValue {
                name: "realm",
                value: "\"unterminated",
                defect: crate::helpers::quoted_string::QuotedStringDefect::NotQuoted,
            })
        );
        assert!(r
            .unwrap_err()
            .message()
            .starts_with("Invalid quoted-string in auth-param 'realm': "));
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
        let r = crate::helpers::quoted_string::validate_quoted_string(&s);
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("ends with escape"));
    }

    /// Two `Invalid character` sentences that a `String` made
    /// indistinguishable: the octet is read under `auth-param`'s name in one
    /// and under its value in the other, and the pair below is a single header
    /// value away from each other. Which is also why the bad name needs the
    /// comma — a lone `re@alm=xy` never reaches the parameter loop, the
    /// token68 heuristic above it takes an unquoted value behind a non-`token`
    /// name as evidence that the whole thing is a `token68`.
    #[test]
    fn invalid_character_in_param_value_is_error() {
        assert_eq!(
            validate_challenge_syntax("Basic realm=x@y"),
            Err(ChallengeDefect::ParameterValueCharacter('@'))
        );
        assert_eq!(
            validate_challenge_syntax("Basic re@alm=xy, x=1"),
            Err(ChallengeDefect::ParameterNameCharacter('@'))
        );
        assert_eq!(validate_challenge_syntax("Basic re@alm=xy"), Ok(()));
    }

    #[test]
    fn token68_with_allowed_chars_ok() {
        let r = validate_challenge_syntax("NewSch abc+");
        assert!(r.is_ok());
    }
}
