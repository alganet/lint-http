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
/// Returns Ok(()) if the tag looks like a valid language tag, Err(msg) otherwise.
pub fn validate_language_tag(tag: &str) -> Result<(), String> {
    let s = tag.trim();
    if s.is_empty() {
        return Err("empty language tag".into());
    }

    // Reject control chars or whitespace inside tag
    if s.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err("language tag contains control characters or whitespace".into());
    }

    // Only allow ASCII alphanumerics and hyphen
    if let Some(c) = s.chars().find(|c| !c.is_ascii_alphanumeric() && *c != '-') {
        return Err(format!("invalid character '{}' in language tag", c));
    }

    // Hyphen placement checks: leading or trailing hyphens are invalid here;
    // consecutive hyphens are rejected below as empty subtags in the split loop.
    if s.starts_with('-') || s.ends_with('-') {
        return Err("invalid hyphen placement in language tag".into());
    }

    // Subtag length checks (1..=8) per RFC 5646
    for sub in s.split('-') {
        if sub.is_empty() {
            return Err("empty subtag in language tag".into());
        }
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
