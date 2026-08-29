// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! The `quoted-string` production: whether a value is one, and what is inside it.
//!
//! **One walk, exposed three ways.** [`quoted_string_interior_chars`] is the
//! walk — it yields the octet each `quoted-pair` stands for and stops at the
//! first defect. [`validate_quoted_string`] asks it only whether it finished;
//! [`unescape_quoted_string`] keeps what it produced. A test here holds the
//! three to that agreement, because they were once three walks.
//!
//! [`QuotedStringDefect`] is why the walk reports rather than returns a bool:
//! four distinct ways the production fails, each carrying the sentence that
//! makes it one, and a `message` that renders the finding. It is one of the four
//! typed defect enums in this tree, and the model the others are converging on.
//!
//! **This module owns the escape rule, and the list splitters deliberately do
//! not.** `quoted-pair` is defined as part of `quoted-string` and nowhere else,
//! so outside one a backslash is an ordinary octet. The splitters in
//! `helpers::headers` track quote parity themselves and do not honour a
//! top-level escape — not duplication but the two productions disagreeing, and
//! honouring it out there once let a stray backslash swallow every later member.

use crate::helpers::shown::shown_in_finding;

/// The index of the DQUOTE that closes the `quoted-string` starting at `s[0]`,
/// or `None` when nothing closes it.
///
/// Grammars that put a `quoted-string` in the middle of a construct --
/// `expectation`'s value with `parameters` behind it, `Warning`'s `warn-text`
/// with a `warn-date` behind it -- have to know where the construct ends before
/// they can look at what follows. [`validate_quoted_string`] judges a slice
/// someone else has already cut, which is the question after this one.
///
/// The escape rule is the splitters' and [`quoting_is_balanced`](crate::helpers::list::quoting_is_balanced)'s: a backslash
/// inside the string suppresses the next octet. Both call sites had transcribed
/// this loop by hand, identically, which is two copies of a decision that has to
/// agree with three other functions in this file.
///
/// Returns `None` when `s` does not open with a DQUOTE either -- there is no
/// `quoted-string` to find the end of.
///
/// cite(RFC 9110 § 5.6.4): "quoted-string  = DQUOTE *( qdtext / quoted-pair ) DQUOTE"
/// cite(RFC 9110 § 5.6.4): "quoted-pair    = "\" ( HTAB / SP / VCHAR / obs-text )"
pub fn quoted_string_end(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    if bytes.first() != Some(&b'"') {
        return None;
    }
    let mut i = 1usize;
    let mut prev_backslash = false;
    while i < bytes.len() {
        let b = bytes[i];
        if prev_backslash {
            prev_backslash = false;
        } else if b == b'\\' {
            prev_backslash = true;
        } else if b == b'"' {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// The `*( qdtext / quoted-pair )` between a `quoted-string`'s two DQUOTEs,
/// with nothing inside it examined.
///
/// The five paragraphs that used to stand above this line described
/// [`validate_quoted_string`] — its two octet sets, its `chars`-not-`as_bytes`
/// walk — and were separated from it by two other items, so `rustdoc` published
/// them against a function that strips two characters and reads none. They now
/// live on [`quoted_string_interior_chars`], which is where that walk went.
///
/// A lone DQUOTE strips its prefix and then has no suffix left to strip, so the
/// one-character string is `None` rather than an empty interior — which is the
/// distinction the production draws, `DQUOTE DQUOTE` being the shortest value it
/// generates. [`validate_quoted_string`] and [`unescape_quoted_string`] both ask
/// this rather than each slicing the ends off, because "is this quoted at all"
/// has to be one answer for the pair of them.
// cite(RFC 9110 § 5.6.4): "quoted-string  = DQUOTE *( qdtext / quoted-pair ) DQUOTE"
pub fn quoted_string_interior(val: &str) -> Option<&str> {
    val.strip_prefix('"')?.strip_suffix('"')
}

/// What a `quoted-string`'s interior can fail to be.
///
/// Data rather than a sentence for the same reason [`WordDefect`](crate::helpers::word::WordDefect) is: the two
/// functions that read this interior word their failures against the whole
/// value, and the walk sees only the inside of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotedStringDefect {
    /// An octet after a backslash that `quoted-pair` does not admit. A backslash
    /// does not make anything quotable: the escaped octet has its own set, and
    /// it is not `qdtext`'s.
    BadQuotedPair,
    /// A DQUOTE inside the interior that no backslash introduced. The interior
    /// runs between the production's two DQUOTEs, so a third one closes the
    /// value early and what follows derives from nothing.
    UnescapedQuote,
    /// A control octet `qdtext` excludes. HTAB is not one of them — it is in
    /// both alphabets.
    ControlCharacter,
    /// A backslash with nothing after it. `quoted-pair` is two octets.
    TrailingEscape,
}

impl QuotedStringDefect {
    /// The finding, worded against the whole `quoted-string` rather than against
    /// the interior the walk was given — which is what every caller embedding
    /// this in its own message expects to read.
    pub fn message(self, val: &str) -> String {
        // Escaped, always. Three of the four defects below are *about* an octet
        // that would corrupt the sentence carrying it — a control character, a
        // lone backslash, an unescaped DQUOTE — so a message that pasted the
        // value in raw put the thing it was reporting into its own text, where a
        // reader saw a truncated line or an escape nobody wrote. The fourth is
        // no different: `qdtext` admits HTAB and `obs-text`.
        let shown = shown_in_finding(val);
        match self {
            Self::BadQuotedPair => {
                format!("Invalid quoted-pair in quoted-string: '{}'", shown)
            }
            Self::UnescapedQuote => format!("Unescaped quote in quoted-string: '{}'", shown),
            Self::ControlCharacter => format!("Control character in quoted-string: '{}'", shown),
            Self::TrailingEscape => {
                format!("Quoted-string ends with escape character: '{}'", shown)
            }
        }
    }
}

/// The one walk over a `quoted-string`'s interior, yielding each character of
/// the value it stands for.
///
/// **This pair used to be two walks and the cost was visible from outside.**
/// [`validate_quoted_string`] measured the interior and [`unescape_quoted_string`]
/// called it and then measured the interior again to substitute, so every caller
/// that wanted the content paid for two passes and the second one needed an
/// `expect` to throw away an `Err` the first had already ruled out. Two owners
/// for one production is also how they drift: a `quoted-pair` fix had to be made
/// in both, in lockstep, and nothing but attention held them together.
///
/// The walk is over `chars` and not over `as_bytes`, and the difference is the
/// whole of `obs-text`. A caller reading a value through
/// [`combined_field_value_as_written`](crate::helpers::headers::combined_field_value_as_written) holds one `char` per octet, so %xE9 in it
/// is `U+00E9` — which `as_bytes` re-encodes as the *two* octets %xC3 %xA9, a
/// pair the sender did not write. `to_str` callers cannot tell the two walks
/// apart, because that reader admits no octet at or above %x80 at all.
///
/// The two octet sets are worth reading side by side, because the difference
/// between them is the whole of this function. `qdtext` is what may appear bare;
/// `quoted-pair` is what may appear after a backslash. HTAB and `obs-text` are in
/// both — HTTP is not Structured Fields, and the same-looking helper in
/// `structured_fields.rs` is right to reject exactly what this one accepts.
///
/// Substitution is unconditional and there is no escape table here, nor should
/// there ever be: the sentence is about the octet *following* the backslash and
/// not about any interpretation of it, so `\n` in a `quoted-string` is the
/// letter n.
///
/// The iterator stops at the first defect, which is what makes a caller
/// collecting it and a caller draining it report the same thing.
///
/// **It yields the character and not `(char, was_escaped)`**, which is what the
/// handover asking for this scanner specified. Nothing in the tree distinguishes
/// an octet a backslash introduced from the same octet written bare, and neither
/// does the production: a `quoted-pair` *is* the octet after the backslash, by
/// the recipient sentence below. The two functions here differ in whether they
/// keep the character, not in whether they know how it got there, so a flag no
/// caller reads would be a second answer to a question nobody asks. It goes in
/// when a caller needs it, like every other shared answer in this module.
///
// cite(RFC 9110 § 5.6.4): "quoted-string  = DQUOTE *( qdtext / quoted-pair ) DQUOTE"
// cite(RFC 9110 § 5.6.4): "qdtext         = HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text"
// cite(RFC 9110 § 5.6.4): "quoted-pair    = "\" ( HTAB / SP / VCHAR / obs-text )"
// cite(RFC 9110 § 5.6.4): "Recipients that process the value of a quoted-string MUST handle a quoted-pair as if it were replaced by the octet following the backslash."
pub fn quoted_string_interior_chars(inner: &str) -> QuotedStringChars<'_> {
    QuotedStringChars {
        chars: inner.chars(),
        stopped: false,
    }
}

/// [`quoted_string_interior_chars`]'s iterator.
pub struct QuotedStringChars<'a> {
    chars: std::str::Chars<'a>,
    stopped: bool,
}

impl Iterator for QuotedStringChars<'_> {
    type Item = Result<char, QuotedStringDefect>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.stopped {
            return None;
        }
        let c = self.chars.next()?;

        if c == '\\' {
            let Some(escaped) = self.chars.next() else {
                self.stopped = true;
                return Some(Err(QuotedStringDefect::TrailingEscape));
            };
            if !(escaped == '\t' || ('\u{20}'..='\u{7e}').contains(&escaped) || escaped >= '\u{80}')
            {
                self.stopped = true;
                return Some(Err(QuotedStringDefect::BadQuotedPair));
            }
            return Some(Ok(escaped));
        }
        if c == '"' {
            self.stopped = true;
            return Some(Err(QuotedStringDefect::UnescapedQuote));
        }
        if (c < '\u{20}' && c != '\t') || c == '\u{7f}' {
            self.stopped = true;
            return Some(Err(QuotedStringDefect::ControlCharacter));
        }
        Some(Ok(c))
    }
}

/// Whether the value is a well-formed `quoted-string`, with nothing kept.
///
/// The walk is [`quoted_string_interior_chars`]'s and is run once; a caller that
/// also wants the content asks [`unescape_quoted_string`] instead of asking
/// both.
///
/// **The `String` is a convenience and not the only way to reach the answer.**
/// The defect is [`QuotedStringDefect`], and a caller that wants to word the
/// finding in its own field's terms — the way `Alt-Svc`'s parameter reader words
/// `WordDefect` — walks [`quoted_string_interior_chars`] and matches the
/// variant. Every one of the thirty-odd callers today embeds this sentence in
/// its own, so the flattening costs nothing yet; the moment one of them needs
/// to say something different about a `quoted-pair` than about a stray DQUOTE,
/// it has somewhere to go that is not a second copy of the walk.
pub fn validate_quoted_string(val: &str) -> Result<(), String> {
    let Some(inner) = quoted_string_interior(val) else {
        return Err(format!(
            "Quoted-string not properly quoted: '{}'",
            shown_in_finding(val)
        ));
    };
    for step in quoted_string_interior_chars(inner) {
        step.map_err(|defect| defect.message(val))?;
    }
    Ok(())
}

/// Check whether a quoted-string's unescaped inner content, after trimming,
/// is empty. Returns Ok(true) if the inner content is empty after trimming,
/// Ok(false) if it contains any non-whitespace character, or Err(msg) if the
/// input is not a well-formed quoted-string. This is useful for treating
/// quoted-empty values (e.g., `""` or `"   "`) as empty for presence checks.
pub fn quoted_string_inner_trimmed_is_empty(val: &str) -> Result<bool, String> {
    // Reuse `unescape_quoted_string` to perform unescaping and validation
    match unescape_quoted_string(val) {
        Ok(s) => Ok(s.trim().is_empty()),
        Err(e) => Err(e),
    }
}

/// Unescape a well-formed HTTP `quoted-string` value and return its inner contents.
/// - Input must include surrounding DQUOTE characters (e.g., `"a\"b"`).
/// - Returns `Ok(inner_string)` on success or `Err(msg)` if the input is not a valid quoted-string.
///
/// **One pass.** This used to call [`validate_quoted_string`] and then walk the
/// interior a second time to substitute, which is two readings of one production
/// and needed an `expect` to discard an `Err` the first reading had already ruled
/// out. Both functions now drain [`quoted_string_interior_chars`], which measures
/// and substitutes in the same step, so the pair cannot disagree and neither pays
/// for the other.
pub fn unescape_quoted_string(val: &str) -> Result<String, String> {
    let Some(inner) = quoted_string_interior(val) else {
        return Err(format!(
            "Quoted-string not properly quoted: '{}'",
            shown_in_finding(val)
        ));
    };
    let mut out = String::with_capacity(inner.len());
    for step in quoted_string_interior_chars(inner) {
        out.push(step.map_err(|defect| defect.message(val))?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `qdtext` and `quoted-pair` allow different octets after their respective
    /// positions, and a backslash does not widen the set to "anything".
    #[test]
    fn quoted_pair_octet_is_constrained() {
        // HTAB / SP / VCHAR / obs-text may follow a backslash.
        assert!(validate_quoted_string("\"\\\t\"").is_ok());
        assert!(validate_quoted_string("\"\\ \"").is_ok());
        assert!(validate_quoted_string("\"\\a\"").is_ok());
        assert!(validate_quoted_string("\"\\\u{80}\"").is_ok());
        // The other controls may not, escaped or otherwise.
        assert!(validate_quoted_string("\"\\\u{1}\"").is_err());
        assert!(validate_quoted_string("\"\\\n\"").is_err());
        assert!(validate_quoted_string("\"\\\u{7f}\"").is_err());
    }

    /// HTTP's `qdtext` admits HTAB and obs-text, which is the opposite of the
    /// Structured Fields String rule -- same shape, different document.
    #[test]
    fn qdtext_admits_htab_and_obs_text() {
        assert!(validate_quoted_string("\"a\tb\"").is_ok());
        assert!(validate_quoted_string("\"caf\u{e9}\"").is_ok());
        assert!(validate_quoted_string("\"a\u{1}b\"").is_err());
    }

    #[test]
    fn validate_quoted_string_control_char_reports_violation() {
        let s = "\"bad\x01str\"";
        let res = validate_quoted_string(s);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("Control character"));
    }

    #[test]
    fn validate_quoted_string_unterminated_reports_violation() {
        let s = "\"unfinished";
        let res = validate_quoted_string(s);
        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .contains("Quoted-string not properly quoted"));
    }

    #[test]
    fn validate_quoted_string_extra_chars_reports_violation() {
        let s = "\"abc\"x";
        let res = validate_quoted_string(s);
        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .contains("Quoted-string not properly quoted"));
    }

    #[test]
    fn validate_quoted_string_with_escaped_quote_is_valid() {
        let s = "\"a\\\"b\""; // "a\"b"
        let res = validate_quoted_string(s);
        assert!(res.is_ok());
    }

    #[test]
    fn validate_quoted_string_unescaped_quote_reports_violation() {
        // inner unescaped quote before the terminating quote
        let s = "\"a\"b\""; // "a"b"
        let res = validate_quoted_string(s);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("Unescaped quote"));
    }

    #[test]
    fn validate_quoted_string_ends_with_escape_reports_violation() {
        let s = "\"abc\\\""; // ends with escaped state before final quote
        let res = validate_quoted_string(s);
        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .contains("Quoted-string ends with escape character"));
    }

    #[test]
    fn quoted_string_inner_trimmed_is_empty_true_cases() {
        assert!(quoted_string_inner_trimmed_is_empty("\"\"").unwrap());
        assert!(quoted_string_inner_trimmed_is_empty("\"   \"").unwrap());
    }

    /// The one walk, read directly: each character of the value the interior
    /// stands for.
    #[test]
    fn quoted_string_interior_chars_yields_the_octet_the_quoted_pair_stands_for() {
        let read = |inner: &str| quoted_string_interior_chars(inner).collect::<Vec<_>>();
        assert_eq!(
            read("a\\\"b"),
            vec![Ok('a'), Ok('"'), Ok('b')],
            "an escaped DQUOTE is a quoted-pair and the value it stands for is the DQUOTE"
        );
        // Substitution is unconditional: the octet following the backslash, not
        // an interpretation of it. `\n` is the letter n.
        assert_eq!(read("\\n"), vec![Ok('n')]);
        // HTAB is in both alphabets, bare and escaped.
        assert_eq!(read("\t"), vec![Ok('\t')]);
        assert_eq!(read("\\\t"), vec![Ok('\t')]);
    }

    /// Each defect, and that the walk stops on the first one — which is what
    /// makes a caller draining it and a caller collecting it report the same
    /// thing.
    #[test]
    fn quoted_string_interior_chars_stops_at_the_first_defect() {
        let first = |inner: &str| {
            quoted_string_interior_chars(inner)
                .find(|step| step.is_err())
                .map(|step| step.unwrap_err())
        };
        assert_eq!(first("a\"b"), Some(QuotedStringDefect::UnescapedQuote));
        assert_eq!(first("a\u{1}b"), Some(QuotedStringDefect::ControlCharacter));
        assert_eq!(first("a\u{7f}"), Some(QuotedStringDefect::ControlCharacter));
        assert_eq!(first("a\\"), Some(QuotedStringDefect::TrailingEscape));
        assert_eq!(first("a\\\u{1}"), Some(QuotedStringDefect::BadQuotedPair));
        assert_eq!(first("plain"), None);

        // Nothing is yielded after the defect, so a collector cannot see past it.
        let after: Vec<_> = quoted_string_interior_chars("a\"bcd").collect();
        assert_eq!(after.len(), 2, "the 'a', then the defect, then nothing");
    }

    /// The pair used to be two walks and could disagree; now one drains the
    /// scanner and the other collects it, so every value they are given gets one
    /// verdict. `obs-text` is the case that matters: `qdtext` admits it, and a
    /// byte walk would have split it into two octets nobody sent.
    #[test]
    fn validate_and_unescape_agree_on_every_value_because_they_are_one_walk() {
        let cases = [
            "\"\"",
            "\"a\"",
            "\"a\\\"b\"",
            "\"a\\\\b\"",
            "\"\t\"",
            "\"a\"b\"",
            "\"a\u{1}\"",
            "\"a\\\"",
            "\"unterminated",
            "a\"",
            "\"",
            "",
        ];
        for case in cases {
            assert_eq!(
                validate_quoted_string(case).is_ok(),
                unescape_quoted_string(case).is_ok(),
                "the two disagreed on {:?}",
                case
            );
            if let Err(v) = validate_quoted_string(case) {
                assert_eq!(
                    Some(v),
                    unescape_quoted_string(case).err(),
                    "same value, two messages, for {:?}",
                    case
                );
            }
        }
    }

    #[test]
    fn unescape_quoted_string_basic_cases() {
        assert_eq!(unescape_quoted_string("\"\"").unwrap(), "");
        assert_eq!(unescape_quoted_string("\"a\"").unwrap(), "a");
        assert_eq!(unescape_quoted_string("\"a\\\"b\"").unwrap(), "a\"b");
        assert_eq!(unescape_quoted_string("\"a\\\\b\"").unwrap(), "a\\b");
    }

    /// `qdtext` admits `obs-text`, so an octet at or above %x80 inside a
    /// `quoted-string` is conforming and has to come back out as itself. Both
    /// functions used to walk `as_bytes`, which re-encoded the one `char` per
    /// octet a caller reading through `combined_field_value_as_written` holds:
    /// %xE9 went in and %xC3 %xA9 came out, so a finding naming the octet named
    /// a pair the sender never wrote.
    #[test]
    fn an_obs_text_octet_survives_the_round_trip_as_one_octet() {
        let as_written: String = [b'"', 0xE9, b'x', b'"']
            .iter()
            .map(|&b| b as char)
            .collect();
        assert!(validate_quoted_string(&as_written).is_ok());
        let inner = unescape_quoted_string(&as_written).expect("qdtext admits obs-text");
        assert_eq!(inner.chars().count(), 2);
        assert_eq!(inner.chars().next().map(|c| c as u32), Some(0xE9));

        // The same octet after a backslash: `quoted-pair` admits it too.
        let escaped: String = [b'"', b'\\', 0xE9, b'"']
            .iter()
            .map(|&b| b as char)
            .collect();
        let inner = unescape_quoted_string(&escaped).expect("quoted-pair admits obs-text");
        assert_eq!(inner.chars().map(|c| c as u32).collect::<Vec<_>>(), [0xE9]);
    }

    #[test]
    fn unescape_quoted_string_invalid_cases() {
        assert!(unescape_quoted_string("\"unterminated").is_err());
        assert!(unescape_quoted_string("\"bad\x01\"").is_err()); // control char
        assert!(unescape_quoted_string("\"a\"b\"").is_err()); // unescaped quote
    }

    #[test]
    fn quoted_string_inner_trimmed_is_empty_false_and_invalid_cases() {
        assert!(!quoted_string_inner_trimmed_is_empty("\"a\"").unwrap());
        // escaped quote inside is a non-empty inner
        assert!(!quoted_string_inner_trimmed_is_empty("\"\\\"\"").unwrap());
        // unterminated quoted-string is an error
        assert!(quoted_string_inner_trimmed_is_empty("\"unterminated").is_err());
    }

    #[test]
    fn quoted_string_inner_unescaped_quote_reports_error() {
        let s = "\"a\"b\""; // inner unescaped quote before terminating quote
        let r = quoted_string_inner_trimmed_is_empty(s);
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("Unescaped quote"));
    }

    /// Three of the four `quoted-string` defects are about an octet that would
    /// corrupt the sentence reporting it. Each message names the octet instead
    /// of carrying it.
    #[test]
    fn a_quoted_string_finding_does_not_paste_in_the_octet_it_is_about() {
        // A control octet: raw, it truncated the line a reader saw.
        let m = validate_quoted_string("\"a\u{1}b\"").expect_err("a control octet is reported");
        assert_eq!(m, "Control character in quoted-string: '\\\"a\\u{1}b\\\"'");
        assert!(!m.contains('\u{1}'), "{m}");

        // A backslash with nothing after it, which reads as an escape to
        // whoever the message reaches next.
        let m = validate_quoted_string("\"a\\\"").expect_err("a trailing escape is reported");
        assert!(m.contains("ends with escape character"), "{m}");
        assert!(m.contains("\\\\"), "{m}");

        // A DQUOTE that closes the value early: unescaped, the message reads as
        // quoting something.
        let m = validate_quoted_string("\"a\"b\"").expect_err("an unescaped quote is reported");
        assert!(m.contains("Unescaped quote"), "{m}");
        assert!(m.contains("\\\"a\\\"b\\\""), "{m}");

        // An unquoted value is escaped by the same rule, and `obs-text` stays
        // legible: naming the octet is `describe_octet`'s job, not this one's.
        assert_eq!(
            validate_quoted_string("caf\u{e9}").expect_err("not a quoted-string"),
            "Quoted-string not properly quoted: 'café'"
        );
    }

    #[test]
    fn validate_quoted_string_cases() {
        // valid
        assert!(validate_quoted_string("\"ok\"").is_ok());
        // not quoted
        assert!(validate_quoted_string("noquotes").is_err());
        // unescaped quote inside
        assert!(validate_quoted_string("\"bad\"inner\"").is_err());
        // control character inside
        assert!(validate_quoted_string("\"a\x01b\"").is_err());
        // ends with escape char
        assert!(validate_quoted_string("\"abc\\\"").is_err());
    }
}
