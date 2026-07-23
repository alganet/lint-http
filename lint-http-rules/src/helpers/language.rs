// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

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
/// Returns Ok(()) if the tag looks like a valid language tag, Err(msg) otherwise.
pub fn validate_language_tag(tag: &str) -> Result<(), String> {
    let s = tag.trim();
    if s.is_empty() {
        return Err("empty language tag".into());
    }

    // Reject control chars or whitespace inside tag
    // cite(RFC 5646 § 2.1): "Whitespace is not permitted in a language tag."
    if s.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err("language tag contains control characters or whitespace".into());
    }

    // Only allow ASCII alphanumerics and hyphen
    // cite(RFC 5646 § 2.1): "Subtags, in turn, are a sequence of alphanumeric characters (letters and digits), distinguished and separated from other subtags in a tag by a hyphen ("-", [Unicode] U+002D)."
    if let Some(c) = s.chars().find(|c| !c.is_ascii_alphanumeric() && *c != '-') {
        return Err(format!("invalid character '{}' in language tag", c));
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
        return Err("invalid hyphen placement in language tag".into());
    }

    for sub in s.split('-') {
        if sub.is_empty() {
            return Err("empty subtag in language tag".into());
        }
        // cite(RFC 5646 § 2.1): "All subtags have a maximum length of eight characters."
        if sub.len() > 8 {
            return Err(format!("subtag '{}' is too long (max 8 chars)", sub));
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
        let res = validate_language_tag("en--US");
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("empty subtag"));
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
