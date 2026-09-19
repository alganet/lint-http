// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Cookie-related helpers used by cookie-related rules.

/// The ways a `Set-Cookie` `Path` attribute fails, named rather than described.
///
/// The two halves are not the same kind of finding, and the type is what makes
/// that legible. [`Empty`](Self::Empty) and [`NotAbsolute`](Self::NotAbsolute)
/// are not *syntax* errors at all — RFC 6265 § 5.2.4 has the user agent replace
/// such a value with the default-path, so the cookie still works and the server
/// has merely written something that does nothing. The remaining four are
/// grammar: § 4.1.1's `path-value` admits neither of them.
///
/// A caller that wants to report the two halves differently now can. Before
/// this was an enum, one of the tests below asked
/// `msg.contains("should start with '/'") || msg.contains("invalid")` — an `||`
/// that exists precisely because a `String` cannot say which defect it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CookiePathDefect<'a> {
    /// No value after trimming. § 5.2.4 substitutes the default-path.
    Empty,
    /// Present but not rooted at `/`; § 5.2.4 substitutes the default-path.
    /// Carries the value **as written**, untrimmed, because that is what the
    /// server sent and the trim is this function's own tolerance.
    NotAbsolute(&'a str),
    /// A `%` that no two hex digits follow. Delegated to
    /// [`crate::helpers::percent_encoding::percent_encoding_defect`], which owns the
    /// production and phrases this one — and is carried typed rather than
    /// rendered, so a caller can report *which* of the two it was under the
    /// name the whole tree uses for it.
    PercentEncoding(crate::helpers::percent_encoding::PercentEncodingDefect<'a>),
    /// A byte at or above %x80. `path-value` is built on `CHAR` = %x01-7F, so
    /// non-ASCII derives from nothing and has to be percent-encoded.
    NonAscii(usize),
    /// A `CTL`, which `path-value` excludes by name. HTAB is one of these, not
    /// a [`Whitespace`](Self::Whitespace).
    ControlCharacter(usize),
    /// SP, which `CHAR` admits and this profile does not. Stricter than the
    /// grammar on purpose.
    Whitespace(usize),
}

impl CookiePathDefect<'_> {
    /// The finding fragment. Callers embed this in a sentence naming the
    /// attribute, which is why it does not name it itself.
    pub fn message(&self) -> String {
        match self {
            Self::Empty => "Path attribute is empty".to_string(),
            Self::NotAbsolute(written) => {
                format!("Path should start with '/': '{written}'")
            }
            Self::PercentEncoding(defect) => defect.message(),
            Self::NonAscii(at) => format!("Path contains non-ASCII character at byte {at}"),
            Self::ControlCharacter(at) => format!("Path contains control character at byte {at}"),
            Self::Whitespace(at) => format!("Path contains whitespace character at byte {at}"),
        }
    }
}

/// Validate a `Path` attribute value from a `Set-Cookie` header.
///
/// Rules enforced:
/// - Must not be empty
/// - Must start with `/`
/// - Must not contain ASCII control characters (0x00-0x1F or 0x7F)
/// - Must not contain literal whitespace characters (space, tab)
/// - Percent-encodings ("%" followed by two hex digits) are accepted
///
/// The byte offsets in the character defects count into the **trimmed** value,
/// while [`CookiePathDefect::NotAbsolute`] carries the value as written. That
/// asymmetry was already here when the errors were strings; naming the variants
/// is what made it visible enough to write down.
pub fn validate_cookie_path(s: &str) -> Result<(), CookiePathDefect<'_>> {
    let v = crate::helpers::headers::trim_ows(s);
    // Empty and non-`/` values are not a *syntax* error: §5.2.4 has the user
    // agent replace them with the default-path. That semantics is cited at the
    // sole call site (`cookie_path_valid`); here we flag them as the
    // latent misconfiguration they are and go on to enforce the character
    // grammar below.
    if v.is_empty() {
        return Err(CookiePathDefect::Empty);
    }
    if !v.starts_with('/') {
        return Err(CookiePathDefect::NotAbsolute(s));
    }

    // Validate percent-encodings using shared helper to avoid duplicate logic
    if let Some(defect) = crate::helpers::percent_encoding::percent_encoding_defect(v) {
        return Err(CookiePathDefect::PercentEncoding(defect));
    }

    // The loop holds the server to §4.1.1's `path-value = <any CHAR except CTLs
    // or ";">`: CHAR is %x01-7F (so non-ASCII is rejected) and CTLs are excluded
    // (the `";"` is excluded structurally — the caller splits on it). Whitespace
    // is a stricter-than-grammar profile (space is a legal CHAR; see the RFC
    // 9110 §5.6.3 SpecRef), except tab, which is itself a CTL.
    // cite(RFC 6265 § 4.1.1): "Servers SHOULD NOT send Set-Cookie headers that fail to conform to the following grammar:"
    let bytes = v.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        // Reject non-ASCII bytes (require percent-encoding for non-ASCII)
        if b >= 0x80 {
            return Err(CookiePathDefect::NonAscii(i));
        }
        // Reject control chars and DEL
        if b <= 0x1f || b == 0x7f {
            return Err(CookiePathDefect::ControlCharacter(i));
        }
        // Reject ASCII space and horizontal tab explicitly
        if b == b' ' || b == b'\t' {
            return Err(CookiePathDefect::Whitespace(i));
        }
        i += 1;
    }

    Ok(())
}

/// Representation of a parsed `Set-Cookie` value and some derived metadata.
/// SameSite attribute values as defined in RFC 6265bis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SameSite {
    /// Explicit `SameSite=Strict`.
    Strict,
    /// Explicit `SameSite=Lax`.
    Lax,
    /// Explicit `SameSite=None`.
    None,
    /// Attribute not specified or unrecognized; browsers treat this as the
    /// default (which is effectively `Lax` in modern implementations).
    Unspecified,
}

pub struct Cookie {
    pub name: String,
    pub value: String,
    /// Effective cookie domain (lowercased, no leading dot)
    pub domain: String,
    /// True when the cookie was set with no `Domain` attribute.  Per RFC 6265
    /// §5.3 such a cookie is "host-only" and its domain is the request-host;
    /// §5.4 then permits sending it only to that exact host, never a subdomain.
    pub host_only: bool,
    /// Effective path attribute
    pub path: String,
    pub secure: bool,
    /// Expiration time, if known (computed from Max-Age or Expires).  A value
    /// less-or-equal to the transaction timestamp is treated as expired.
    pub expiration: Option<chrono::DateTime<chrono::Utc>>,
    /// Parsed SameSite directive (if any).
    pub same_site: SameSite,
}

impl Cookie {
    /// Returns `true` if the cookie is considered expired at `when`.
    pub fn is_expired_at(&self, when: chrono::DateTime<chrono::Utc>) -> bool {
        if let Some(exp) = self.expiration {
            exp <= when
        } else {
            false
        }
    }

    /// Domain-match check following RFC 6265 §5.1.3, refined by the host-only
    /// inclusion rule of §5.4: a host-only cookie matches only its exact host.
    /// Only the host portion of the request URI should be supplied (no port).
    // cite(RFC 6265 § 5.1.3, label: cookie domain-match): "A string domain-matches a given domain string if at least one of the following conditions hold"
    pub fn domain_matches(&self, request_host: &str) -> bool {
        let req = request_host.to_ascii_lowercase();
        let dom = self.domain.as_str();
        if req == dom {
            return true;
        }
        // A host-only cookie (set without a Domain attribute) is bound to its
        // exact host; §5.4 lists request-host-*identical* as the only inclusion
        // condition for it, so it never matches a subdomain even though the
        // suffix test below would otherwise accept one.
        // cite(RFC 6265 § 5.4): "The cookie's host-only-flag is true and the canonicalized request-host is identical to the cookie's domain."
        if self.host_only {
            return false;
        }
        req.ends_with(&format!(".{}", dom))
    }

    /// Path-match per RFC 6265 §5.1.4.  `request_path` should be the path
    /// component extracted from the request-target (leading '/' or "/").
    // cite(RFC 6265 § 5.1.4, label: cookie path-match): "A request-path path-matches a given cookie-path if at least one of the following conditions holds"
    pub fn path_matches(&self, request_path: &str) -> bool {
        let cookie_path = self.path.as_str();
        // RFC 6265 §5.1.4:
        // 1. If the cookie-path and the request-path are identical, the
        //    path-matches.
        if request_path == cookie_path {
            return true;
        }
        // 2. If the cookie-path is a prefix of the request-path, and either
        //    the last character of the cookie-path is %x2F ("/") or the
        //    character following the cookie-path in the request-path is %x2F
        //    ("/"), then the path-matches.
        if !request_path.starts_with(cookie_path) {
            return false;
        }
        if cookie_path.ends_with('/') {
            return true;
        }
        matches!(request_path.as_bytes().get(cookie_path.len()), Some(b'/'))
    }
}

/// One `cookie-av`: an attribute name, and the value it carries if any.
///
/// `value` distinguishes "no `=` was written" (`None`) from "an `=` with
/// nothing after it" (`Some("")`), because the two are different defects for
/// the flag attributes: `Secure` takes no value at all, so `Secure=` is a
/// sender writing one.
// cite(RFC 6265 § 4.1.1): "cookie-av         = expires-av / max-age-av / domain-av / path-av / secure-av / httponly-av / extension-av"
pub struct Attribute<'a> {
    pub name: &'a str,
    pub value: Option<&'a str>,
}

impl Attribute<'_> {
    /// Whether this is the named attribute, compared case-insensitively.
    // cite(RFC 6265 § 5.2.1): "If the attribute-name case-insensitively matches the string "Expires", the user agent MUST process the cookie-av as follows."
    pub fn is(&self, name: &str) -> bool {
        self.name.eq_ignore_ascii_case(name)
    }

    /// Whether a value was written after the `=`.
    pub fn has_value(&self) -> bool {
        self.value.is_some_and(|v| !v.is_empty())
    }
}

/// The cookie one `Set-Cookie` field line is about, named as a finding names it.
///
/// A response is allowed to set many cookies and does — RFC 6265 § 3 tells an
/// origin server not to fold them onto one line ("Origin servers SHOULD NOT
/// fold multiple Set-Cookie header fields into a single header field"), so each
/// line is a separate cookie with its own name, value and attributes. A rule
/// reading the field therefore answers once per cookie, and two of its findings
/// carry the same sentence unless each says which cookie it is about.
///
/// The cookie-name is what tells them apart: § 4.1.1 puts it first on the line,
/// before the `=`. A line that wrote no `=` has no name to give, and the empty
/// string is how this says so — [`about_cookie`] then leaves the sentence
/// alone, because a finding naming `cookie ''` names nothing.
// cite(RFC 6265 § 4.1.1): "cookie-pair       = cookie-name "=" cookie-value cookie-name       = token"
pub fn set_cookie_name(line: &str) -> &str {
    let (pair, _) = split_set_cookie(line);
    match pair.split_once('=') {
        Some((name, _)) => crate::helpers::headers::trim_ows(name),
        None => "",
    }
}

/// What a finding claims, and then which cookie it claims it of.
///
/// The name goes after the sentence rather than into it: what is wrong is what
/// an operator reads first, and which of ten cookies it is wrong about is what
/// they read next to find the line. Written once here so that the rules reading
/// `Set-Cookie` cannot say it three different ways.
pub fn about_cookie(name: &str, sentence: impl std::fmt::Display) -> String {
    if name.is_empty() {
        sentence.to_string()
    } else {
        format!("{sentence} (cookie '{name}')")
    }
}

/// Split one `Set-Cookie` field line into its cookie-pair and its attributes.
///
/// The parser below and the rule that reports attribute defects were each
/// splitting this line themselves, on the same two characters, and neither
/// could say what the other did with an empty segment. The pair comes back as
/// written — judging it is the caller's job — and the attributes come back with
/// the empty segments a stray `;` produces already dropped.
// cite(RFC 6265 § 4.1.1): "set-cookie-string = cookie-pair *( ";" SP cookie-av )"
pub fn split_set_cookie(line: &str) -> (&str, impl Iterator<Item = Attribute<'_>>) {
    let mut segments = line.split(';').map(str::trim);
    // `split` always yields at least one segment, so the pair is whatever
    // stands before the first `;` — possibly empty, which is a defect the
    // caller names.
    let pair = segments.next().unwrap_or("");
    let attributes = segments
        .filter(|segment| !segment.is_empty())
        .map(|segment| match segment.split_once('=') {
            Some((name, value)) => Attribute {
                name: crate::helpers::headers::trim_ows(name),
                value: Some(crate::helpers::headers::trim_ows(value)),
            },
            None => Attribute {
                name: segment,
                value: None,
            },
        });
    (pair, attributes)
}

/// The host the request was sent to, which a cookie with no `Domain` is bound
/// to.
// cite(RFC 6265 § 5.3): "Set the cookie's host-only-flag to true."
fn default_domain(request_uri: &str) -> String {
    let Some(idx) = request_uri.find("://") else {
        // An unparseable request-target leaves nothing to bind to, and an empty
        // domain matches no request later.
        return String::new();
    };
    let authority = request_uri[idx + 3..].split('/').next().unwrap_or("");
    authority
        .split(':')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase()
}

/// The default-path of a cookie set by a request to `request_uri`.
///
/// The branches are § 5.1.4's numbered steps, in its order.
// cite(RFC 6265 § 5.1.4): "The user agent MUST use an algorithm equivalent to the following algorithm to compute the default-path of a cookie:"
fn default_path(request_uri: &str) -> String {
    let Some(p) = crate::helpers::request_target::extract_path_from_request_target(request_uri)
    else {
        return "/".into();
    };
    // Step 2. Quoted here only as its tail: the step opens "If the uri-path is
    // empty or if the first character of the uri-" and the document's line
    // break lands inside `uri-path`, so the sentence cannot be quoted whole.
    // cite(RFC 6265 § 5.1.4): "output %x2F ("/") and skip the remaining steps."
    if !p.starts_with('/') {
        return "/".into();
    }
    // cite(RFC 6265 § 5.1.4): "If the uri-path contains no more than one %x2F ("/") character, output %x2F ("/") and skip the remaining step."
    if p.matches('/').count() <= 1 {
        return "/".into();
    }
    // cite(RFC 6265 § 5.1.4): "Output the characters of the uri-path from the first character up to, but not including, the right-most %x2F ("/")."
    match p.rfind('/') {
        Some(0) | None => "/".into(),
        Some(pos) => p[..pos].to_string(),
    }
}

/// Parse a `Set-Cookie` header value into a `Cookie` struct, using the
/// request URI and timestamp to derive default domain/path and compute
/// expiration.  Returns `None` if the value cannot be parsed at all.
pub fn parse_set_cookie(
    header_value: &str,
    request_uri: &str,
    timestamp: chrono::DateTime<chrono::Utc>,
) -> Option<Cookie> {
    let (pair, attributes) = split_set_cookie(header_value);
    if pair.is_empty() {
        return None;
    }

    let mut kv = pair.splitn(2, '=');
    let name = crate::helpers::headers::trim_ows(kv.next()?).to_string();
    let value = crate::helpers::headers::trim_ows(kv.next().unwrap_or("")).to_string();

    let mut domain_attr: Option<String> = None;
    let mut path_attr: Option<String> = None;
    let mut secure = false;
    let mut max_age: Option<i64> = None;
    let mut expires_attr: Option<chrono::DateTime<chrono::Utc>> = None;
    let mut same_site = SameSite::Unspecified;

    for attr in attributes {
        let val_opt = attr.value;
        match attr.name.to_ascii_lowercase().as_str() {
            "domain" => {
                if let Some(v) = val_opt {
                    // cookie domains ignore leading dot per modern spec
                    let d = v.trim_start_matches('.').to_ascii_lowercase();
                    domain_attr = Some(d);
                }
            }
            "path" => {
                if let Some(v) = val_opt {
                    // The user agent ignores such an attribute and uses the
                    // default-path instead.  We mirror that by only assigning
                    // when the value is syntactically valid.
                    // cite(RFC 6265 § 5.2.4, label: cookie Path attribute): "If the attribute-value is empty or if the first character of the attribute-value is not %x2F ("/"):"
                    if v.starts_with('/') {
                        path_attr = Some(v.to_string());
                    }
                }
            }
            "secure" => {
                secure = true;
            }
            "max-age" => {
                if let Some(v) = val_opt {
                    if let Ok(n) = v.parse::<i64>() {
                        max_age = Some(n);
                    }
                }
            }
            "expires" => {
                if let Some(v) = val_opt {
                    if let Ok(dt) = crate::http_date::parse_http_date_to_datetime(v) {
                        expires_attr = Some(dt);
                    }
                }
            }
            "samesite" => {
                if let Some(v) = val_opt {
                    let norm = v.to_ascii_lowercase();
                    same_site = match norm.as_str() {
                        "strict" => SameSite::Strict,
                        "lax" => SameSite::Lax,
                        "none" => SameSite::None,
                        _ => SameSite::Unspecified,
                    };
                }
            }
            _ => {}
        }
    }

    // No Domain attribute → host-only cookie bound to the request-host.
    // cite(RFC 6265 § 5.3): "Set the cookie's host-only-flag to true."
    let host_only = domain_attr.is_none();
    let domain = domain_attr.unwrap_or_else(|| default_domain(request_uri));

    let path = path_attr.unwrap_or_else(|| default_path(request_uri));

    // compute expiration time from Max-Age or Expires
    let expiration = if let Some(n) = max_age {
        // treat non-positive as already expired
        if n <= 0 {
            Some(timestamp)
        } else {
            Some(timestamp + chrono::Duration::seconds(n))
        }
    } else {
        expires_attr
    };

    Some(Cookie {
        name,
        value,
        domain,
        host_only,
        path,
        secure,
        expiration,
        same_site,
    })
}

/// The first character in a `cookie-value` that is not a `cookie-octet`.
///
/// `cookie-value = *cookie-octet / ( DQUOTE *cookie-octet DQUOTE )` — a value
/// wrapped in a matching pair of outer `DQUOTE`s is unwrapped first, so what
/// is scanned is always the bare `*cookie-octet` alternative. A single stray
/// `"` (length 1) does not match the wrapped form and is scanned as written,
/// which correctly reports it: `cookie-octet` excludes `"` in both forms.
// cite(RFC 6265 § 4.1.1): "cookie-value      = *cookie-octet / ( DQUOTE *cookie-octet DQUOTE ) cookie-octet      = %x21 / %x23-2B / %x2D-3A / %x3C-5B / %x5D-7E"
pub fn find_invalid_cookie_octet(value: &str) -> Option<char> {
    let inner = if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
        &value[1..value.len() - 1]
    } else {
        value
    };
    fn is_cookie_octet(c: char) -> bool {
        matches!(c as u32, 0x21 | 0x23..=0x2B | 0x2D..=0x3A | 0x3C..=0x5B | 0x5D..=0x7E)
    }
    inner.chars().find(|&c| !is_cookie_octet(c))
}

/// Parse a `Cookie` request header value into name/value pairs.
/// Does not attempt to enforce stronger syntax rules; caller should trim.
pub fn parse_cookie_header(s: &str) -> Vec<(String, String)> {
    s.split(';')
        .filter_map(|piece| {
            let mut kv = piece.splitn(2, '=');
            let name = crate::helpers::headers::trim_ows(kv.next()?).to_string();
            let value = crate::helpers::headers::trim_ows(kv.next().unwrap_or("")).to_string();
            Some((name, value))
        })
        .collect()
}

/// Reconstruct a simple "live" cookie store from an origin-scoped history
/// and return cookies that would be considered applicable at the given time.
///
/// This mirrors the logic used by the stateful rules to avoid duplicating
/// heap allocations. `TransactionHistory::iter()` yields items in
/// newest-first order; this helper walks them in reverse so that cookies are
/// applied from oldest to newest.
pub fn build_cookie_store(
    history: &crate::transaction_history::TransactionHistory,
    at: chrono::DateTime<chrono::Utc>,
) -> Vec<Cookie> {
    let history_items: Vec<_> = history.iter().collect();
    let mut live_cookies: Vec<Cookie> = Vec::new();

    for prev in history_items.iter().rev() {
        if let Some(resp) = &prev.response {
            for s in crate::helpers::headers::field_lines(&resp.headers, "set-cookie") {
                if let Some(cookie) = parse_set_cookie(s, &prev.request.uri, prev.timestamp) {
                    live_cookies.retain(|c| {
                        !(c.name == cookie.name
                            && c.domain == cookie.domain
                            && c.path == cookie.path)
                    });

                    if !cookie.is_expired_at(prev.timestamp) {
                        live_cookies.push(cookie);
                    }
                }
            }
        }
    }

    // filter out cookies expired by the evaluation timestamp
    live_cookies.retain(|c| !c.is_expired_at(at));
    live_cookies
}

/// Does RFC 6265 § 5.1.1's algorithm read an instant out of this value?
///
/// **This is the recipient's parse, and it is not § 5.6.7's.** § 5.2.1 sends a
/// user agent here and nowhere else for an `Expires` attribute, so this — not
/// [`crate::http_date::is_valid_http_date`] — is what decides whether the
/// attribute names an instant. The two disagree constantly and in one
/// direction: § 5.1.1 tokenizes on delimiters and reads what the grammar in
/// § 4.1.1 will not.
///
/// Three consequences the callers care about, all of them ordinary traffic:
///
/// * `-` is a `delimiter` (%x2D falls in %x20-2F), so `30-Aug-2026` is the
///   three tokens `30`, `Aug`, `2026` and reads exactly as `30 Aug 2026` does.
/// * `year` is `2*4DIGIT`, and steps 3 and 4 map 70-99 onto 19xx and 0-69 onto
///   20xx, so `27` is 2027.
/// * The zone is never looked at. No production matches `GMT` or `UTC`, both
///   are skipped as unmatched tokens, and step 6 fixes the result as UTC
///   regardless of what was written.
///
/// So this returns `false` only for a value that names no instant to anybody —
/// which is the whole reason it is separate from a grammar check.
///
// cite(RFC 6265 § 5.1.1): "The user agent MUST use an algorithm equivalent to
// the following algorithm to parse a cookie-date."
pub fn cookie_date_is_readable(s: &str) -> bool {
    // cite(RFC 6265 § 5.1.1): "delimiter       = %x09 / %x20-2F / %x3B-40 / %x5B-60 / %x7B-7E"
    fn is_delimiter(b: u8) -> bool {
        b == 0x09
            || (0x20..=0x2F).contains(&b)
            || (0x3B..=0x40).contains(&b)
            || (0x5B..=0x60).contains(&b)
            || (0x7B..=0x7E).contains(&b)
    }

    const MONTHS: [&str; 12] = [
        "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
    ];

    // Every production below is digits followed by `non-digit *OCTET`: the
    // digits are read and whatever trails them is ignored rather than rejected,
    // which is why `2026;` and `08:49:37.5` parse. A run longer than the
    // production's maximum is not a match at all — that is what stops a
    // four-digit year being read as a day-of-month.
    fn leading_digits(token: &[u8], min: usize, max: usize) -> Option<(u64, &[u8])> {
        let len = token
            .iter()
            .position(|b| !b.is_ascii_digit())
            .unwrap_or(token.len());
        if len < min || len > max {
            return None;
        }
        let n = std::str::from_utf8(&token[..len]).ok()?.parse().ok()?;
        Some((n, &token[len..]))
    }

    let (mut hour, mut minute, mut second) = (None, None, None);
    let (mut day_of_month, mut month, mut year) = (None, None, None);

    for token in s
        .as_bytes()
        .split(|&b| is_delimiter(b))
        .filter(|t| !t.is_empty())
    {
        // cite(RFC 6265 § 5.1.1): "hms-time        = time-field ":" time-field ":" time-field"
        if hour.is_none() {
            if let Some((h, m, sec)) = parse_hms(token) {
                (hour, minute, second) = (Some(h), Some(m), Some(sec));
                continue;
            }
        }
        // cite(RFC 6265 § 5.1.1): "day-of-month    = 1*2DIGIT ( non-digit *OCTET )"
        if day_of_month.is_none() {
            if let Some((n, _)) = leading_digits(token, 1, 2) {
                day_of_month = Some(n);
                continue;
            }
        }
        // cite(RFC 6265 § 5.1.1): "month           = ( "jan" / "feb" / "mar" / "apr" /"
        if month.is_none() && token.len() >= 3 {
            if let Some(index) = MONTHS
                .iter()
                .position(|m| token[..3].eq_ignore_ascii_case(m.as_bytes()))
            {
                month = Some(index as u64 + 1);
                continue;
            }
        }
        // cite(RFC 6265 § 5.1.1): "year            = 2*4DIGIT ( non-digit *OCTET )"
        if year.is_none() {
            if let Some((n, _)) = leading_digits(token, 2, 4) {
                year = Some(n);
                continue;
            }
        }
    }

    let (Some(hour), Some(minute), Some(second)) = (hour, minute, second) else {
        return false;
    };
    let (Some(day_of_month), Some(_), Some(year)) = (day_of_month, month, year) else {
        return false;
    };

    // cite(RFC 6265 § 5.1.1): "If the year-value is greater than or equal to 70 and less than or"
    let year = match year {
        70..=99 => year + 1900,
        0..=69 => year + 2000,
        _ => year,
    };

    // cite(RFC 6265 § 5.1.1): "the day-of-month-value is less than 1 or greater than 31,"
    (1..=31).contains(&day_of_month) && year >= 1601 && hour <= 23 && minute <= 59 && second <= 59
}

/// `hms-time`, split out only because three `time-field`s do not fit a
/// condition. Returns `None` unless all three are present and digit-led.
fn parse_hms(token: &[u8]) -> Option<(u64, u64, u64)> {
    fn field(rest: &[u8]) -> Option<(u64, &[u8])> {
        let len = rest
            .iter()
            .position(|b| !b.is_ascii_digit())
            .unwrap_or(rest.len());
        if len == 0 || len > 2 {
            return None;
        }
        let n = std::str::from_utf8(&rest[..len]).ok()?.parse().ok()?;
        Some((n, &rest[len..]))
    }
    let (hour, rest) = field(token)?;
    let (minute, rest) = field(rest.strip_prefix(b":")?)?;
    let (second, _) = field(rest.strip_prefix(b":")?)?;
    Some((hour, minute, second))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[test]
    fn valid_paths() {
        assert!(validate_cookie_path("/").is_ok());
        assert!(validate_cookie_path("/login").is_ok());
        assert!(validate_cookie_path("/foo/bar").is_ok());
        assert!(validate_cookie_path("/foo%20bar").is_ok());
        assert!(validate_cookie_path("/a%2Fb").is_ok());
    }

    #[test]
    fn invalid_paths() {
        assert!(validate_cookie_path("").is_err());
        assert!(validate_cookie_path("login").is_err());
        assert!(validate_cookie_path("/has space").is_err());
        assert!(validate_cookie_path("/has\tTab").is_err());
        assert!(validate_cookie_path("/%ZZ").is_err());
        assert!(validate_cookie_path("/%2").is_err());
        assert!(validate_cookie_path("/%2G").is_err());
        assert!(validate_cookie_path("/a\x00b").is_err());
        // Non-ASCII characters should be rejected (require percent-encoding)
        assert!(validate_cookie_path("/café").is_err());
        assert!(validate_cookie_path("/ünicode").is_err());
    }
    #[test]
    fn parse_cookie_header_basic() {
        let vals = parse_cookie_header("a=1; b=two;empty=");
        assert_eq!(
            vals,
            vec![
                ("a".into(), "1".into()),
                ("b".into(), "two".into()),
                ("empty".into(), "".into()),
            ]
        );
    }

    #[test]
    fn parse_set_cookie_defaults_and_attributes() {
        // basic name/value and default domain/path from a multi-segment URI
        let ts = chrono::Utc::now();
        let c = parse_set_cookie("SID=abc123", "https://example.com/foo/bar", ts).unwrap();
        assert_eq!(c.name, "SID");
        assert_eq!(c.value, "abc123");
        assert_eq!(c.domain, "example.com");
        assert_eq!(c.path, "/foo".to_string());
        assert!(!c.secure);
        assert!(c.expiration.is_none());
        assert_eq!(c.same_site, SameSite::Unspecified);

        // default path when request path has only root
        let c0 = parse_set_cookie("x=1", "https://example.com/", ts).unwrap();
        assert_eq!(c0.path, "/");
        assert_eq!(c0.same_site, SameSite::Unspecified);

        // explicit domain and path, secure, max-age
        let c2 = parse_set_cookie(
            "id=1; Domain=EXAMPLE.com; Path=/; Secure; Max-Age=10; SameSite=Strict",
            "https://example.com/anything",
            ts,
        )
        .unwrap();
        assert_eq!(c2.domain, "example.com");
        assert_eq!(c2.path, "/");
        assert!(c2.secure);
        assert!(c2.expiration.is_some());
        assert!(c2.expiration.unwrap() > ts);
        assert_eq!(c2.same_site, SameSite::Strict);

        // path attribute that doesn't start with slash should be ignored and
        // default-path applied instead (RFC 6265 §5.2.4).
        let c3 = parse_set_cookie(
            "foo=bar; Path=not/a/slash",
            "https://example.com/some/path",
            ts,
        )
        .unwrap();
        // default-path of /some
        assert_eq!(c3.path, "/some");
        assert_eq!(c3.same_site, SameSite::Unspecified);
    }

    #[test]
    fn cookie_domain_path_matching() {
        let ts = chrono::Utc::now();
        let base = parse_set_cookie(
            "a=1; Domain=example.com; Path=/sub",
            "https://example.com/",
            ts,
        )
        .unwrap();
        // hostname equal
        assert!(base.domain_matches("example.com"));
        // subdomain suffix
        assert!(base.domain_matches("foo.example.com"));
        assert!(!base.domain_matches("other.com"));
        // path prefix
        assert!(base.path_matches("/sub/page"));
        assert!(!base.path_matches("/other"));
    }

    #[test]
    fn cookie_expiration_checks() {
        let ts = chrono::Utc::now();
        let c = parse_set_cookie("x=1; Max-Age=1", "https://example.com/", ts).unwrap();
        assert!(!c.is_expired_at(ts));
        assert!(c.is_expired_at(ts + chrono::Duration::seconds(2)));
        let c2 = parse_set_cookie("y=1; Max-Age=0", "https://example.com/", ts).unwrap();
        assert!(c2.is_expired_at(ts));
        // expires attribute parsing using httpdate formatting
        let exp_str = httpdate::fmt_http_date(std::time::SystemTime::now());
        let header = format!("z=1; Expires={}", exp_str);
        let c3 = parse_set_cookie(&header, "https://example.com/", ts).unwrap();
        assert!(c3.expiration.is_some());
    }

    #[test]
    fn build_store_override_keeps_new() {
        let ts = chrono::Utc::now();
        let t1 = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("set-cookie", "a=one")],
        );
        let mut t1 = t1;
        t1.timestamp = ts - chrono::Duration::seconds(20);
        let t2 = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("set-cookie", "a=two")],
        );
        let mut t2 = t2;
        t2.timestamp = ts - chrono::Duration::seconds(10);
        // history newest first order is provided by constructor
        let history =
            crate::transaction_history::TransactionHistory::from_transactions(vec![t2, t1]);
        let store = build_cookie_store(&history, ts);
        assert_eq!(store.len(), 1);
        assert_eq!(store[0].value, "two");
    }

    #[test]
    fn build_store_domain_path_matching() {
        let ts = chrono::Utc::now();
        let mut tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("set-cookie", "b=1; Domain=example.com; Path=/foo")],
        );
        tx.timestamp = ts - chrono::Duration::seconds(10);
        let history = crate::transaction_history::TransactionHistory::from_transactions(vec![tx]);
        let store = build_cookie_store(&history, ts);
        assert_eq!(store.len(), 1);
        let c = &store[0];
        assert!(c.domain_matches("example.com"));
        assert!(c.domain_matches("sub.example.com"));
        assert!(c.path_matches("/foo/bar"));
        assert!(!c.path_matches("/bar"));
    }

    #[test]
    fn parse_set_cookie_bad_uri_domain() {
        let ts = chrono::Utc::now();
        let c = parse_set_cookie("n=1", "not-a-uri", ts).unwrap();
        // domain falls back to empty string
        assert_eq!(c.domain, "");
        assert_eq!(c.same_site, SameSite::Unspecified);
    }

    #[test]
    fn build_store_filters_expired_and_overrides() {
        let ts = chrono::Utc::now();
        // create history with two responses that set the same name
        let mut t1 = crate::test_helpers::make_test_transaction();
        t1.request.uri = "https://example.com/".into();
        t1.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[(
                "set-cookie",
                "a=1; Max-Age=3600",
            )]),
            body_length: None,
            body_interrupted: false,
            trailers: None,
        });
        t1.timestamp = ts - chrono::Duration::seconds(10);

        let mut t2 = crate::test_helpers::make_test_transaction();
        t2.request.uri = "https://example.com/".into();
        t2.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[(
                "set-cookie",
                "a=2; Max-Age=0",
            )]),
            body_length: None,
            body_interrupted: false,
            trailers: None,
        });
        t2.timestamp = ts - chrono::Duration::seconds(5);

        // newest-first: t2 happened later than t1
        let history =
            crate::transaction_history::TransactionHistory::from_transactions(vec![t2, t1]);

        let store = build_cookie_store(&history, ts);
        // second cookie expired immediately, so no live cookies remain
        assert!(store.is_empty());
    }

    #[test]
    fn samesite_values_parsed() {
        let ts = chrono::Utc::now();
        let c_strict = parse_set_cookie("x=1; SameSite=Strict", "https://a/", ts).unwrap();
        assert_eq!(c_strict.same_site, SameSite::Strict);
        let c_lax = parse_set_cookie("x=1; SameSite=Lax", "https://a/", ts).unwrap();
        assert_eq!(c_lax.same_site, SameSite::Lax);
        let c_none = parse_set_cookie("x=1; SameSite=None", "https://a/", ts).unwrap();
        assert_eq!(c_none.same_site, SameSite::None);
        let c_weird = parse_set_cookie("x=1; SameSite=Weird", "https://a/", ts).unwrap();
        assert_eq!(c_weird.same_site, SameSite::Unspecified);
    }

    /// § 5.1.1 against the forms § 5.6.7 refuses. The first group is what a
    /// user agent reads happily and `rfc1123-date` does not admit; the second
    /// is what nobody reads.
    #[rstest]
    #[case("Wed, 21 Oct 2015 07:28:00 GMT", true)]
    #[case("Sun, 30-Aug-2026 02:23:34 GMT", true)]
    #[case("Mon, 30-Aug-27 01:13:44 GMT", true)]
    #[case("Mon, 31 Aug 2026 00:16:39 UTC", true)]
    #[case("Sunday, 06-Nov-94 08:49:37 GMT", true)]
    // Delimiters are structural, not decorative: the tokens are all that matter.
    #[case("21;Oct;2015;07:28:00", true)]
    // Two-digit years split at 69: both of these are in range once mapped.
    #[case("Wed, 21 Oct 70 07:28:00 GMT", true)]
    #[case("Wed, 21 Oct 69 07:28:00 GMT", true)]
    #[case("NotADate", false)]
    // A time and a month and no year.
    #[case("Wed, 21 Oct 07:28:00 GMT", false)]
    // A year and a month and no time.
    #[case("Wed, 21 Oct 2015 GMT", false)]
    // Step 5's bounds, one at a time.
    #[case("Wed, 32 Oct 2015 07:28:00 GMT", false)]
    #[case("Wed, 21 Oct 1500 07:28:00 GMT", false)]
    #[case("Wed, 21 Oct 2015 24:28:00 GMT", false)]
    #[case("Wed, 21 Oct 2015 07:60:00 GMT", false)]
    #[case("Wed, 21 Oct 2015 07:28:60 GMT", false)]
    // `year` is at most 4DIGIT, so a five-digit run matches no production.
    #[case("Wed, 21 Oct 20155 07:28:00 GMT", false)]
    #[case("", false)]
    fn cookie_date_readability(#[case] value: &str, #[case] readable: bool) {
        assert_eq!(
            cookie_date_is_readable(value),
            readable,
            "§ 5.1.1 disagrees about '{value}'"
        );
    }
}
