// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! A scheme name: which characters of a value offer themselves as one, whether
//! what they spell is one, and where the `://` that separates it from an
//! authority stands.
//!
//! **Finding a scheme and judging one are two questions, and keeping them apart
//! is what this module is for.** [`scheme_prefix`] names the candidate without
//! looking at it, because a caller often wants the name itself — which
//! alternative of a grammar the value took, or which scheme's rules govern the
//! authority beside it. [`validate_scheme_name`] reads the production and
//! nothing else, for a field whose whole value *is* a scheme name.
//! [`scheme_if_present`] is the pairing of the two and adds nothing to either.
//!
//! **`scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )` was written out three
//! times in this tree before it had one home**, and the third copy was found
//! only because it sat in the module named for the header field that reached it.
//! The production admits `+`, `-`, `.` and every DIGIT *after* a letter and
//! nowhere else, which is the half a character-set loop drops and the reason
//! `9x` and `+http` are schemes that never started rather than schemes with a
//! bad character in them.
//!
//! **[`scheme_authority_marker`] is here because the `://` is the scheme's own
//! delimiter**, and reading it is the same refusal the production is: a `://`
//! further along a value is ordinary data — a URL carried in a query parameter
//! is the everyday case — and everything before a real marker is a scheme,
//! which admits no component delimiter and is never empty. What sits *after*
//! the marker is [`super::uri`]'s and its callers' question.
/// The characters a value offers as its scheme — everything before the colon
/// that delimits one — or `None` when the value offers none.
///
/// Only a colon in the *first* component can delimit a scheme. A colon is an
/// ordinary path or query character, so the scan stops at the first "/", "?"
/// or "#": past those delimiters a colon is data, not a scheme separator.
///
/// Whether what it returns *is* a scheme name is [`validate_scheme_name`]'s
/// question, and the two are separate because a caller often needs the name
/// itself — which of the two alternatives of a grammar the value took, or
/// which scheme's rules apply to the authority beside it.
// cite(RFC 3986 § 3.3): "pchar         = unreserved / pct-encoded / sub-delims / ":" / "@""
// cite(RFC 3986 § 4.2): "A path segment that contains a colon character (e.g., "this:that") cannot be used as the first segment of a relative-path reference, as it would be mistaken for a scheme name."
pub fn scheme_prefix(s: &str) -> Option<&str> {
    let first_component = &s[..s.find(['/', '?', '#']).unwrap_or(s.len())];
    let colon = first_component.find(':')?;
    Some(&s[..colon])
}

/// The defect of the scheme a value carries, if it carries one at all.
///
/// **The `Some` is the defect and not a sentence**, for the reason
/// [`super::percent_encoding::percent_encoding_defect`] gives beside its own rendered twin: a caller
/// reporting through the catalogue answers with the `uri_scheme_*` def the
/// variant maps to, and one wording its own finding asks
/// [`SchemeNameDefect::message`] for the fragment. There is no rendered twin
/// here because all three callers name the field the scheme came from, and a
/// sentence that begins "Invalid scheme in value" inside one that already says
/// which value it is says it twice.
pub fn scheme_if_present(s: &str) -> Option<SchemeNameDefect<'_>> {
    // The production itself is [`validate_scheme_name`]'s and finding the
    // candidate is [`scheme_prefix`]'s. This function is only the pairing of
    // the two; what a scheme name may be made of is one question with one
    // answer, and it was written out twice here before that function existed.
    //
    // An empty scheme (a value opening with ':') satisfies neither `scheme`, whose
    // `ALPHA` is not optional, nor `segment-nz-nc`, which excludes ':' and so
    // cannot start a relative-path reference either.
    validate_scheme_name(scheme_prefix(s)?).err()
}

/// Byte offset of the `://` that separates a scheme from an authority, or
/// `None` when the value is not in absolute form.
///
/// A bare `s.find("://")` is not that test. `://` occurring later in a value is
/// ordinary data — a URL carried in a query parameter (`?redirect_uri=`,
/// `?next=`, `?url=`) is the everyday case — and reading an authority out of it
/// invents an origin the message never had. Everything before a real marker is
/// the scheme, which admits no component delimiter and is never empty.
///
/// Public because a caller that wants the *question* — is this value in
/// absolute form — and not the origin cannot ask
/// [`super::origin::extract_origin_if_absolute`]: that function answers `None` both for a
/// value with no scheme and for an absolute-form value whose scheme or
/// authority is the finding, and the two need opposite treatment. Reaching for
/// `contains("://")` instead is what the paragraph above is about, and it was
/// written twice in one rule before this was exposed.
// cite(RFC 3986 § 3.1): "scheme      = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )"
pub fn scheme_authority_marker(s: &str) -> Option<usize> {
    let idx = s.find("://")?;
    if idx == 0 || s[..idx].contains(['/', '?', '#']) {
        return None;
    }
    Some(idx)
}

/// Validate a bare scheme name — the production alone, with no ':' to find it by.
///
/// [`scheme_if_present`] locates a scheme inside a larger value and then
/// asks this question of what it found; a field whose whole value *is* a scheme
/// name (`Forwarded`'s `proto`) asks it directly. The production was written out
/// twice before this function existed, and the two copies are the shape three of
/// this tree's bugs already have.
///
/// The leading `ALPHA` is the half a character-set loop drops: `1*` is not what
/// the production says, and `+`, `-`, `.` and every DIGIT are admitted only
/// *after* a letter, so `9x` and `+http` are not scheme names.
// cite(RFC 3986 § 3.1): "scheme      = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )"
// cite(RFC 3986 § 3.1): "Scheme names consist of a sequence of characters beginning with a letter and followed by any combination of letters, digits, plus ("+"), period ("."), or hyphen ("-")."
pub fn validate_scheme_name(scheme: &str) -> Result<(), SchemeNameDefect<'_>> {
    let mut chars = scheme.chars();
    let Some(first) = chars.next() else {
        return Err(SchemeNameDefect::Empty);
    };
    if !first.is_ascii_alphabetic() {
        return Err(SchemeNameDefect::DoesNotBeginWithLetter(scheme));
    }
    for c in chars {
        if !(c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.') {
            return Err(SchemeNameDefect::BadCharacter {
                character: c,
                scheme,
            });
        }
    }
    Ok(())
}

/// What a scheme name fails to be.
///
/// Three variants for the production's two halves, and the split between the
/// last two is the one the production draws and a character-set loop does not:
/// `+`, `-`, `.` and every DIGIT are admitted, but only *after* a letter. So
/// `+http` is not a bad character in a scheme — it is a scheme that never
/// started, and `DoesNotBeginWithLetter` is the answer for `9x` and `+http`
/// alike.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemeNameDefect<'a> {
    /// No scheme name at all. `ALPHA *( ... )` generates nothing empty.
    Empty,
    /// A first character that is not `ALPHA`, carrying the whole name — the
    /// character alone would not show what it is a prefix of.
    DoesNotBeginWithLetter(&'a str),
    /// A character after the first that the production does not admit.
    BadCharacter {
        /// The character.
        character: char,
        /// The scheme it was found in.
        scheme: &'a str,
    },
}

impl SchemeNameDefect<'_> {
    /// The finding fragment. Callers name the field the scheme came from and
    /// put this after it.
    pub fn message(self) -> String {
        match self {
            Self::Empty => "scheme must not be empty".to_string(),
            Self::DoesNotBeginWithLetter(scheme) => {
                format!("scheme '{}' must begin with a letter", scheme)
            }
            Self::BadCharacter { character, scheme } => {
                format!("invalid character '{}' in scheme '{}'", character, scheme)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scheme_validation() {
        assert!(scheme_if_present("1http://ex").is_some());
        assert!(scheme_if_present("ht!tp://ex").is_some());
        assert!(scheme_if_present("/relative").is_none());
        assert!(scheme_if_present("https://ex").is_none());
    }

    /// The production's two halves, and the split the variants make plain:
    /// `+` and every DIGIT are admitted *after* a letter, so `+http` and `9foo`
    /// are not bad characters in a scheme — they are schemes that never
    /// started, and only `ht_tp` and `ht%tp` are the other thing.
    #[test]
    fn scheme_name_needs_a_leading_letter() {
        assert!(validate_scheme_name("http").is_ok());
        assert!(validate_scheme_name("coap+ws").is_ok());
        assert!(validate_scheme_name("a").is_ok());
        // Every one of these is a `token`, which is why a rule reaching for
        // `tchar` where the sentence says "URI scheme name" accepts them.
        assert_eq!(
            validate_scheme_name("9foo"),
            Err(SchemeNameDefect::DoesNotBeginWithLetter("9foo"))
        );
        assert_eq!(
            validate_scheme_name("+http"),
            Err(SchemeNameDefect::DoesNotBeginWithLetter("+http"))
        );
        assert_eq!(
            validate_scheme_name("ht_tp"),
            Err(SchemeNameDefect::BadCharacter {
                character: '_',
                scheme: "ht_tp"
            })
        );
        assert_eq!(
            validate_scheme_name("ht%tp"),
            Err(SchemeNameDefect::BadCharacter {
                character: '%',
                scheme: "ht%tp"
            })
        );
        assert_eq!(validate_scheme_name(""), Err(SchemeNameDefect::Empty));
    }

    #[test]
    fn colon_inside_a_path_or_query_is_not_a_scheme_delimiter() {
        // `pchar` admits ':' inside a segment, so these are all well-formed
        // absolute-path references with no scheme at all.
        assert_eq!(scheme_if_present("/foo:bar"), None);
        assert_eq!(scheme_if_present("/v1/entities/x:batchGet"), None);
        assert_eq!(scheme_if_present("/users/urn:uuid:1"), None);
        assert_eq!(scheme_if_present("/a?x=b:c"), None);
        assert_eq!(scheme_if_present("/a#f:g"), None);
        // A colon in the first segment of a relative-path reference *is* read
        // as a scheme, which is why RFC 3986 forbids it there.
        assert!(scheme_if_present("this:that").is_none());
        assert!(scheme_if_present("1this:that").is_some());
    }

    #[test]
    fn scheme_prefix_names_the_candidate_without_judging_it() {
        assert_eq!(scheme_prefix("https://ex"), Some("https"));
        assert_eq!(scheme_prefix("about:blank"), Some("about"));
        // Not a scheme name, but it is what the value offered as one — saying so
        // is the caller's, which is the whole reason this is separate.
        assert_eq!(scheme_prefix("1http://ex"), Some("1http"));
        assert_eq!(scheme_prefix(":foo"), Some(""));
        // Past a component delimiter a colon is data.
        assert_eq!(scheme_prefix("/foo:bar"), None);
        assert_eq!(scheme_prefix("/a?x=b:c"), None);
        assert_eq!(scheme_prefix("/a#f:g"), None);
        assert_eq!(scheme_prefix("//host/p"), None);
        assert_eq!(scheme_prefix(""), None);
    }

    #[test]
    fn empty_scheme_is_rejected() {
        let defect = scheme_if_present(":foo").expect("empty scheme must be flagged");
        assert_eq!(defect, SchemeNameDefect::Empty);
        assert!(defect.message().contains("must not be empty"));
    }
}
