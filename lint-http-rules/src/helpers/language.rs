// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

/// The ways a language tag fails, named rather than described.
///
/// Seven variants for seven branches, and the split matters because they are
/// not all the same strength. [`Empty`](Self::Empty),
/// [`WhitespaceOrControl`](Self::WhitespaceOrControl) and
/// [`BadCharacter`](Self::BadCharacter) are the character set. The hyphen and
/// subtag variants come from one sentence — a tag is a sequence of subtags
/// separated by hyphens — read three ways, so a leading hyphen, a doubled one
/// and a trailing one are each a subtag that is not there.
/// [`DoesNotBeginWithLetter`](Self::DoesNotBeginWithLetter) is the one thing
/// RFC 4647's `language-range` and RFC 5646's `language` agree on where they
/// otherwise disagree: neither may open with a digit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LanguageTagDefect<'a> {
    /// Nothing there. Note that nothing is trimmed first — see the function.
    Empty,
    /// A control octet or whitespace inside the tag.
    WhitespaceOrControl,
    /// An octet outside ASCII alphanumerics and `-`, carrying the character.
    BadCharacter(char),
    /// A leading or trailing `-`, which describes a subtag that is not there.
    HyphenPlacement,
    /// The first subtag opens with something other than a letter.
    DoesNotBeginWithLetter,
    /// Two adjacent hyphens: an empty subtag.
    EmptySubtag,
    /// A subtag over eight characters, carrying the subtag itself.
    SubtagTooLong(&'a str),
}

impl LanguageTagDefect<'_> {
    /// The finding fragment. Callers embed this after naming the field the tag
    /// was read from, which is why it does not name one.
    pub fn message(self) -> String {
        match self {
            Self::Empty => "empty language tag".to_string(),
            Self::WhitespaceOrControl => {
                "language tag contains control characters or whitespace".to_string()
            }
            Self::BadCharacter(c) => format!("invalid character '{c}' in language tag"),
            Self::HyphenPlacement => "invalid hyphen placement in language tag".to_string(),
            Self::DoesNotBeginWithLetter => "language tag does not begin with a letter".to_string(),
            Self::EmptySubtag => "empty subtag in language tag".to_string(),
            Self::SubtagTooLong(sub) => format!("subtag '{sub}' is too long (max 8 chars)"),
        }
    }
}

/// Conservative BCP 47 language tag validator used by rules.
///
/// This validator is intentionally permissive compared to full RFC 5646 grammar
/// but rejects common mistakes: invalid characters, empty subtags, overly long
/// subtags (>8), and invalid hyphen placement (leading, trailing, consecutive).
/// It accepts private-use tags (e.g., "x-custom") and registered tags such as
/// "en", "en-US", "zh-Hant", etc.
///
/// What is cited below is § 2.1's prose and not its ABNF, and the permissiveness
/// is the whole reason. The ABNF is normative here -- § 2.1 presents it as the
/// syntax of a language tag, with none of the disclaiming RFC 9651 attaches to
/// its own -- but it says far more than this function checks: `language =
/// 2*3ALPHA / 4ALPHA / 5*8ALPHA`, a `region` of exactly 2ALPHA or 3DIGIT, a fixed
/// list of grandfathered tags. Quoting any of that here would claim a check that
/// is not performed. The prose states the few properties that are actually
/// enforced -- subtags are alphanumeric, hyphen-separated, at most eight
/// characters, and no whitespace -- and each sits on the line that enforces it.
///
/// **Nothing is trimmed here, and the line that used to do it silenced the line
/// below it.** `let s = tag.trim()` removed every character `char::is_whitespace`
/// admits — and the next branch exists to *report* exactly those. On an ASCII
/// space the two cancelled out into a wrong-but-harmless silence; on U+00A0,
/// which is how the octet %xA0 reaches this function, it meant `en-US<%xA0>` was
/// validated as `en-US`. The list's own `OWS` is
/// the caller's to strip (§ 5.6.1.1 puts it outside the element), and inside the
/// element the sentence below admits no whitespace at all — so the honest answer
/// is to measure what was passed.
///
/// Returns `Ok(())` if the tag looks like a valid language tag, or the named
/// [`LanguageTagDefect`] otherwise.
pub fn validate_language_tag(tag: &str) -> Result<(), LanguageTagDefect<'_>> {
    let s = tag;
    if s.is_empty() {
        return Err(LanguageTagDefect::Empty);
    }

    // Reject control chars or whitespace inside tag
    // cite(RFC 5646 § 2.1): "Whitespace is not permitted in a language tag."
    if s.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(LanguageTagDefect::WhitespaceOrControl);
    }

    // Only allow ASCII alphanumerics and hyphen
    // cite(RFC 5646 § 2.1): "Subtags, in turn, are a sequence of alphanumeric characters (letters and digits), distinguished and separated from other subtags in a tag by a hyphen ("-", [Unicode] U+002D)."
    if let Some(c) = s.chars().find(|c| !c.is_ascii_alphanumeric() && *c != '-') {
        return Err(LanguageTagDefect::BadCharacter(c));
    }

    // Hyphen placement checks: leading or trailing hyphens are invalid here;
    // consecutive hyphens are rejected below as empty subtags in the split loop.
    //
    // The sentence does not say "no leading hyphen" anywhere -- it says a tag is
    // made of one or more subtags and that a hyphen is what separates them, which
    // leaves a leading, trailing or doubled hyphen describing a subtag that is not
    // there. That is the whole basis for these two checks and the empty-subtag one
    // below, so it is quoted rather than the stronger sentence we might prefer.
    //
    // cite(RFC 5646 § 2.1): "A language tag is composed from a sequence of one or more "subtags", each of which refines or narrows the range of language identified by the overall tag."
    if s.starts_with('-') || s.ends_with('-') {
        return Err(LanguageTagDefect::HyphenPlacement);
    }

    // The first subtag is letters, in both of the productions this function is
    // asked about. RFC 4647's `language-range` opens with `1*8ALPHA`; RFC 5646's
    // `language` opens with `2*3ALPHA / 4ALPHA / 5*8ALPHA`. They disagree about
    // the length and about what may follow, which is why neither is quoted here
    // as the shape of the whole tag — but they agree that a tag or range cannot
    // begin with a digit, so `123-US` is neither, and this function used to
    // accept it as both.
    //
    // cite(RFC 4647 § 2.1): "language-range   = (1*8ALPHA *("-" 1*8alphanum)) / "*""
    // (The production line is quoted with its trailing comment: without it the
    // snippet falls one character under apycite's 20-character floor.)
    // cite(RFC 5646 § 2.1): "language      = 2*3ALPHA            ; shortest ISO 639 code"
    if !s
        .split('-')
        .next()
        .is_some_and(|first| first.chars().all(|c| c.is_ascii_alphabetic()))
    {
        return Err(LanguageTagDefect::DoesNotBeginWithLetter);
    }

    for sub in s.split('-') {
        if sub.is_empty() {
            return Err(LanguageTagDefect::EmptySubtag);
        }
        // cite(RFC 5646 § 2.1): "All subtags have a maximum length of eight characters."
        if sub.len() > 8 {
            return Err(LanguageTagDefect::SubtagTooLong(sub));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_tags() {
        let good = [
            "en",
            "en-US",
            "zh-Hant",
            "sr-Latn-RS",
            "i-klingon",
            "x-custom",
        ];
        for t in &good {
            assert!(validate_language_tag(t).is_ok(), "{} should be valid", t);
        }
    }

    /// Both productions open with letters — `1*8ALPHA` in RFC 4647's range,
    /// `2*3ALPHA / 4ALPHA / 5*8ALPHA` in RFC 5646's tag. They disagree about
    /// nearly everything after that, and agree about this, so it is the one
    /// shape check this permissive validator can make without choosing between
    /// them. `123-US` used to pass as both.
    #[test]
    fn first_subtag_is_letters() {
        for bad in ["123", "123-US", "1", "9x", "1a-BB"] {
            assert!(
                validate_language_tag(bad).is_err(),
                "{bad} does not begin with a letter"
            );
        }
        // A digit later in the tag is fine: `alphanum` allows it, and `es-419`
        // is one of RFC 9110's own examples.
        for good in ["es-419", "en-US", "x-pig-latin", "i-klingon", "de-1901"] {
            assert!(
                validate_language_tag(good).is_ok(),
                "{good} should be valid"
            );
        }
    }

    #[test]
    fn invalid_chars() {
        assert!(validate_language_tag("en_US").is_err());
        assert!(validate_language_tag("en@US").is_err());
    }

    #[test]
    fn invalid_hyphen_placement() {
        assert!(validate_language_tag("-en").is_err());
        assert!(validate_language_tag("en-").is_err());
        assert!(validate_language_tag("en--US").is_err());
    }

    #[test]
    fn empty_subtag_reports_error() {
        assert_eq!(
            validate_language_tag("en--US"),
            Err(LanguageTagDefect::EmptySubtag)
        );
    }

    /// The seven defects are seven answers, and a doubled hyphen must not be
    /// reported as bad hyphen *placement* — that variant is the leading and
    /// trailing case, and a `String` could not hold the two apart.
    #[test]
    fn each_branch_reports_its_own_defect() {
        use LanguageTagDefect as D;
        assert_eq!(validate_language_tag(""), Err(D::Empty));
        assert_eq!(validate_language_tag("en US"), Err(D::WhitespaceOrControl));
        assert_eq!(validate_language_tag("en_US"), Err(D::BadCharacter('_')));
        assert_eq!(validate_language_tag("-en"), Err(D::HyphenPlacement));
        assert_eq!(validate_language_tag("en-"), Err(D::HyphenPlacement));
        assert_eq!(validate_language_tag("en--US"), Err(D::EmptySubtag));
        assert_eq!(
            validate_language_tag("123-US"),
            Err(D::DoesNotBeginWithLetter)
        );
        assert_eq!(
            validate_language_tag("en-abcdefghi"),
            Err(D::SubtagTooLong("abcdefghi"))
        );
    }

    #[test]
    fn subtag_length() {
        let long = "en-abcdefghijkl"; // subtag > 8
        assert!(validate_language_tag(long).is_err());
    }

    #[test]
    fn empty_tag() {
        assert!(validate_language_tag("").is_err());
    }

    #[test]
    fn whitespace_and_control_characters_are_rejected() {
        assert!(validate_language_tag("en us").is_err());
        // ASCII BEL control char
        assert!(validate_language_tag("en\x07US").is_err());
    }

    #[test]
    fn non_ascii_characters_are_rejected() {
        assert!(validate_language_tag("en-ç").is_err());
    }
}
