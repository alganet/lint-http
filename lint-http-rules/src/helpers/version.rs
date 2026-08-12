// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! The `HTTP-version` production, and the one question every version gate asks
//! of it.
//!
//! Two things live here because they are one thing. The production is what an
//! HTTP/1.x start-line carries and what `message_http_version_syntax_valid`
//! reports against; the *major digit* is what a dozen rules actually want when
//! they ask "is this an HTTP/3 message" — and asking that by comparing the
//! whole string against a literal makes every one of those rules depend on the
//! exact spelling some other part of this workspace happened to choose.
//!
//! Only HTTP/1.x messages carry the field. What a capture records for the other
//! two versions is a version number their own specifications state in words,
//! because neither wire format has anywhere to put one.
// cite(RFC 9112 § 2.3): "The version of an HTTP/1.x message is indicated by an HTTP-version field in the start-line."
// cite(RFC 9113 § 8.3.1): "Individual HTTP/2 requests do not carry an explicit indicator of protocol version."
// cite(RFC 9114 § 4.3.1): "HTTP/3 does not define a way to carry the version identifier that is included in the HTTP/1.1 request line."

/// The two decimal digits of an HTTP version number, in the order they are
/// written.
///
/// Kept as digits rather than as a `(u8, u8)` pair because the two are not
/// interchangeable: the first names the wire format, the second is a
/// capability advertisement about the sender.
// cite(RFC 9110 § 2.5): "HTTP's version number consists of two decimal digits separated by a "." (period or decimal point)."
// cite(RFC 9110 § 2.5): "The first digit (major version) indicates the messaging syntax, whereas the second digit (minor version) indicates the highest minor version within that major version to which the sender is conformant (able to understand for future communication)."
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HttpVersion {
    /// The first digit: which messaging syntax carried the message.
    pub major: u8,
    /// The second digit: the highest minor version the sender is conformant
    /// with.
    pub minor: u8,
}

/// Which of the production's three terminals a value failed to match.
///
/// One variant per terminal rather than one "malformed" verdict, because the
/// three are different mistakes: a name in the wrong case, a number that is not
/// two digits around a period, and a character that is not a digit at all.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HttpVersionError {
    /// `HTTP-name "/"` — the value does not begin with the name, written
    /// exactly that way, followed by a solidus.
    Name,
    /// `DIGIT "." DIGIT` — what follows the solidus is not one character, a
    /// period, and one character.
    Shape,
    /// The right shape, but one of the two characters is not a `DIGIT`.
    Digit,
}

impl std::fmt::Display for HttpVersionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The name is a case-sensitive string, which the notation writes as
        // `%s` and the section says again in prose beside the grammar -- so
        // `http/1.1` fails this terminal, and saying which terminal is what
        // separates it from `HTTP/11`.
        // cite(RFC 9112 § 2.3): "HTTP-version is case-sensitive."
        match self {
            Self::Name => f.write_str(
                "it does not begin with the name 'HTTP' -- spelled in exactly that case -- \
                 followed by a '/'",
            ),
            Self::Shape => f.write_str(
                "what follows 'HTTP/' is not one character, a '.', and one character: the \
                 version number is a major digit and a minor digit, and each is a single digit",
            ),
            Self::Digit => f.write_str(
                "the major and minor positions each hold one character, but a character in \
                 one of them is not a decimal digit",
            ),
        }
    }
}

/// Read a value as the `HTTP-version` production.
///
/// The whole production is nine octets and every one of them is fixed: the
/// four of the name, the solidus, a digit, the period, a digit. Reading it
/// byte-wise is the transcription, and it is also what keeps a multi-byte
/// character out of the "single DIGIT" comparison -- `HTTP/é.1` is one
/// character in the major position and two bytes, and a length test that
/// counted bytes would report the wrong terminal.
// cite(RFC 9112 § 2.3, label: HTTP-version): "HTTP-version  = HTTP-name "/" DIGIT "." DIGIT"
// cite(RFC 9112 § A, label: HTTP-name): "HTTP-name = %x48.54.54.50 ; HTTP"
// The core rule stands alone in its section at fifteen characters, under the
// extractor's floor; the comment beside it is part of the same definition and
// carries it over.
// cite(RFC 5234 § B.1, label: DIGIT): "DIGIT          =  %x30-39 ; 0-9"
pub fn parse(value: &str) -> Result<HttpVersion, HttpVersionError> {
    let rest = value.strip_prefix("HTTP/").ok_or(HttpVersionError::Name)?;

    // Three characters, not three bytes: the shape question is about how many
    // characters sit around the period, and the digit question is asked next.
    let mut chars = rest.chars();
    let (Some(major), Some(dot), Some(minor), None) =
        (chars.next(), chars.next(), chars.next(), chars.next())
    else {
        return Err(HttpVersionError::Shape);
    };
    if dot != '.' {
        return Err(HttpVersionError::Shape);
    }
    if !major.is_ascii_digit() || !minor.is_ascii_digit() {
        return Err(HttpVersionError::Digit);
    }

    Ok(HttpVersion {
        major: major as u8 - b'0',
        minor: minor as u8 - b'0',
    })
}

/// Is this the major version `major` -- i.e. is this message's wire format the
/// one that digit names?
///
/// This is the question a version gate is asking, and it is deliberately not a
/// string comparison. A gate written as `version == "HTTP/3"` is a claim about
/// how one particular writer spells the number, so it goes silent the moment
/// the spelling changes and says nothing while it does; reading the digit the
/// specification names leaves nothing to spell.
// cite(RFC 9110 § 2.5): "The first digit (major version) indicates the messaging syntax"
// cite(RFC 9114 § 4.3.1): "HTTP/3 requests implicitly have a protocol version of "3.0"."
// cite(RFC 9113 § 8.3.1): "All HTTP/2 requests implicitly have a protocol version of "2.0""
pub fn is_major(value: &str, major: u8) -> bool {
    matches!(parse(value), Ok(v) if v.major == major)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case("HTTP/1.1", 1, 1)]
    #[case("HTTP/1.0", 1, 0)]
    #[case("HTTP/0.9", 0, 9)]
    #[case("HTTP/2.0", 2, 0)]
    #[case("HTTP/3.0", 3, 0)]
    #[case("HTTP/9.9", 9, 9)]
    fn the_production_generates_these(#[case] value: &str, #[case] major: u8, #[case] minor: u8) {
        assert_eq!(parse(value), Ok(HttpVersion { major, minor }));
    }

    #[rstest]
    // The name is case-sensitive, so the whole terminal fails on one letter.
    #[case("http/1.1", HttpVersionError::Name)]
    #[case("Http/1.1", HttpVersionError::Name)]
    #[case("1.1", HttpVersionError::Name)]
    #[case("", HttpVersionError::Name)]
    #[case("HTTP1.1", HttpVersionError::Name)]
    // Two digits around one period, and neither more nor fewer.
    #[case("HTTP/1", HttpVersionError::Shape)]
    #[case("HTTP/1.", HttpVersionError::Shape)]
    #[case("HTTP/11.0", HttpVersionError::Shape)]
    #[case("HTTP/1.10", HttpVersionError::Shape)]
    #[case("HTTP/1.1.1", HttpVersionError::Shape)]
    #[case("HTTP/1,1", HttpVersionError::Shape)]
    // A minor version this proxy once wrote and no production generates.
    #[case("HTTP/3", HttpVersionError::Shape)]
    // The right shape; the wrong alphabet.
    #[case("HTTP/1.x", HttpVersionError::Digit)]
    #[case("HTTP/x.1", HttpVersionError::Digit)]
    fn the_production_generates_none_of_these(
        #[case] value: &str,
        #[case] expected: HttpVersionError,
    ) {
        assert_eq!(parse(value), Err(expected));
    }

    /// A character in the major position that is one character and two bytes.
    /// A byte-length test would call this the wrong terminal.
    #[test]
    fn a_multibyte_character_is_one_character_in_the_major_position() {
        assert_eq!(parse("HTTP/é.1"), Err(HttpVersionError::Digit));
    }

    #[rstest]
    #[case("HTTP/3.0", 3, true)]
    #[case("HTTP/2.0", 2, true)]
    #[case("HTTP/1.1", 1, true)]
    #[case("HTTP/1.0", 1, true)]
    #[case("HTTP/2.0", 3, false)]
    #[case("HTTP/1.1", 3, false)]
    // Nothing that fails the production names a major version, including the
    // spelling that omitted the minor digit.
    #[case("HTTP/3", 3, false)]
    #[case("http/3.0", 3, false)]
    fn is_major_reads_the_digit(#[case] value: &str, #[case] major: u8, #[case] expected: bool) {
        assert_eq!(is_major(value, major), expected);
    }

    /// The three errors print as three different sentences, because they are
    /// three different mistakes.
    #[test]
    fn each_terminal_names_itself() {
        assert!(HttpVersionError::Name
            .to_string()
            .contains("exactly that case"));
        assert!(HttpVersionError::Shape.to_string().contains("single digit"));
        assert!(HttpVersionError::Digit
            .to_string()
            .contains("decimal digit"));
    }
}
