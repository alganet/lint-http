// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

/// Result of parsing a `Content-Range` header value.
///
/// The `unit` is carried rather than required to be `bytes`. Content-Range's
/// grammar is the same whatever the unit -- there is no unit-specific
/// alternative in the production, so `items 0-1/3` parses by the same rules as
/// `bytes 0-1/3` and is subject to the same validity conditions. What a caller
/// cannot do for an unrecognised unit is relate the range to an octet count,
/// because the positions are counted in units and `Content-Length` is not.
#[derive(Debug, PartialEq, Eq)]
pub enum ContentRange {
    /// Example: `bytes 0-499/1234` or `bytes 0-499/*` (instance_length = None for `*`).
    Satisfied {
        unit: String,
        first: u128,
        last: u128,
        instance_length: Option<u128>,
    },
    /// Example: `bytes */1234` used in `416 Range Not Satisfiable` responses.
    Unsatisfiable { unit: String, instance_length: u128 },
}

impl ContentRange {
    /// The range unit, lowercased -- unit names are case-insensitive.
    pub fn unit(&self) -> &str {
        match self {
            ContentRange::Satisfied { unit, .. } | ContentRange::Unsatisfiable { unit, .. } => unit,
        }
    }
}

/// Split a `Range` field value into its range unit (lowercased) and the
/// unparsed range-set, or `None` when the value is not a `ranges-specifier`.
///
/// This sits beside the `Content-Range` parser because the two fields name one
/// construct: § 14.1 defines a single range-unit token and then points it at
/// three fields, so a caller comparing a request's unit against a response's is
/// comparing two spellings of the same thing.
///
/// The range-set is returned untouched. Which specifiers are legal is decided
/// per unit, so there is nothing generic to check here; the `bytes` ones belong
/// to `range_header_syntax`. Splitting on the *first* `=` is what
/// the grammar says and not a shortcut: `range-unit` is a token, which cannot
/// contain `=`, while an `other-range` may.
///
// cite(RFC 9110 § 14.1): "This general notion of a "range unit" is used in the Accept-Ranges (Section 14.3) response header field to advertise support for range requests, the Range (Section 14.2) request header field to delineate the parts of a representation that are requested, and the Content-Range (Section 14.4) header field to describe which part of a representation is being transferred."
// cite(RFC 9110 § 14.1.1, label: ranges-specifier grammar): "ranges-specifier = range-unit "=" range-set"
// cite(RFC 9110 § 14.1.1): "The range unit name determines what kinds of range-spec are applicable to its own specifiers.  Hence, the following grammar is generic: each range unit is expected to specify requirements on when int-range, suffix-range, and other-range are allowed."
// cite(RFC 9110 § 14.1): "All range unit names are case-insensitive and ought to be registered within the "HTTP Range Unit Registry", as defined in Section 16.5.1."
pub fn split_ranges_specifier(value: &str) -> Option<(String, &str)> {
    let (unit, range_set) = value.trim().split_once('=')?;
    let unit = unit.trim();
    if unit.is_empty() || crate::helpers::token::find_invalid_token_char(unit).is_some() {
        return None;
    }
    Some((unit.to_ascii_lowercase(), range_set.trim()))
}

/// Which of the three numerals a numeric defect was read from.
///
/// The names are § 14.4's own. `complete-length` is the one worth stating: this
/// module's [`ContentRange`] calls the same number `instance_length`, which is
/// what RFC 7233 called it, and one of the two messages this parser produced
/// used each name — so a reader comparing two findings about the same numeral
/// saw two numerals. The grammar quoted throughout this file is 9110's, so the
/// findings say what it says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Numeral {
    /// `first-pos`, before the `-`.
    FirstPos,
    /// `last-pos`, after it.
    LastPos,
    /// `complete-length`, after the `/`.
    CompleteLength,
}

impl Numeral {
    /// The production's name, as a finding spells it.
    fn label(self) -> &'static str {
        match self {
            Self::FirstPos => "first byte-pos",
            Self::LastPos => "last byte-pos",
            Self::CompleteLength => "complete-length",
        }
    }
}

/// What a `Content-Range` field value fails to be.
///
/// The variants follow the value left to right — the field, the `range-unit`,
/// the SP, the `/`, the `-`, the numerals, then the two validity conditions —
/// which is also the order [`parse_content_range`] reads it in, so a defect
/// names how far the parse got.
///
/// The last two are the ones that are not grammar.
/// [`FirstPosAfterLastPos`](Self::FirstPosAfterLastPos) and
/// [`CompleteLengthNotAfterLastPos`](Self::CompleteLengthNotAfterLastPos) come
/// from § 14.4's one sentence about invalidity, and a value that trips either is
/// well-formed by the ABNF and invalid by the prose. A `String` filed them
/// beside the parse failures with nothing marking the difference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentRangeDefect<'a> {
    /// Nothing there, once the field value's own whitespace is off.
    Empty,
    /// A `range-unit` that is not a `token`, carrying it. Not a unit this
    /// parser fails to model — see the parser, which parses those.
    Unit(&'a str),
    /// A value that is a `range-unit` and then stops. `Content-Range` is the
    /// unit, one SP, and a form after it.
    MissingRangeResp,
    /// Whitespace inside the part after the SP, carrying that part. The
    /// production holds exactly one space and it has already been used.
    WhitespaceInRangeResp(&'a str),
    /// No `/`. Both forms have one.
    MissingSlash,
    /// Something before the `/` that starts with `*` but is not exactly `*`.
    /// `unsatisfied-range` opens with a two-character literal, not a wildcard.
    ValueBeforeSlash,
    /// No `-` in what should be an `incl-range`.
    MissingDash,
    /// A `-` with nothing on one side of it.
    MissingPosition,
    /// A numeral that is not `1*DIGIT`, carrying which one and what was there.
    NotDigits {
        /// Which of the three.
        numeral: Numeral,
        /// The characters found in its place.
        value: &'a str,
    },
    /// A `1*DIGIT` numeral too large to represent, carrying which one and what
    /// was there. § 14.1.2 asks recipients to anticipate large numerals rather
    /// than to overflow on them, and this is that anticipation reported: a
    /// position no recipient can represent addresses the octets of no
    /// representation.
    TooLarge {
        /// Which of the three.
        numeral: Numeral,
        /// The numeral as written.
        value: &'a str,
    },
    /// `last-pos` below `first-pos`. The first of § 14.4's two invalidity
    /// conditions, and what makes `last - first` safe for a caller.
    FirstPosAfterLastPos,
    /// `complete-length` at or below `last-pos`. The second condition:
    /// positions are zero-based and inclusive, so a `last-pos` of 499 needs a
    /// length of 500 to be the last unit rather than one past the end.
    CompleteLengthNotAfterLastPos {
        /// The `complete-length` given.
        length: u128,
        /// The `last-pos` it fails to exceed.
        last: u128,
    },
}

impl ContentRangeDefect<'_> {
    /// The finding fragment. Callers name the field and quote the value around
    /// it, which is why this names neither.
    pub fn message(self) -> String {
        match self {
            Self::Empty => "empty header value".to_string(),
            Self::Unit(unit) => format!("invalid range-unit '{}'", unit),
            Self::MissingRangeResp => "missing range/spec".to_string(),
            Self::WhitespaceInRangeResp(rest) => {
                format!("unexpected whitespace in range/spec '{}'", rest)
            }
            Self::MissingSlash => "missing '/' in range/spec".to_string(),
            Self::ValueBeforeSlash => "unexpected value before '/'".to_string(),
            Self::MissingDash => "missing '-' in byte-range".to_string(),
            Self::MissingPosition => "missing first or last byte-pos".to_string(),
            Self::NotDigits { numeral, value } => format!(
                "invalid {}: '{}' is not a 1*DIGIT value",
                numeral.label(),
                value
            ),
            Self::TooLarge { numeral, value } => format!(
                "invalid {}: '{}' is larger than this parser can represent",
                numeral.label(),
                value
            ),
            Self::FirstPosAfterLastPos => "first byte-pos greater than last".to_string(),
            Self::CompleteLengthNotAfterLastPos { length, last } => format!(
                "complete-length {} is not greater than last byte-pos {}",
                length, last
            ),
        }
    }
}

/// Parse a `Content-Range` header value into a [`ContentRange`], or name what it
/// fails to be as a [`ContentRangeDefect`].
///
/// **A value that reaches the unit check always has a unit.** The field value is
/// trimmed and checked for emptiness first, so it opens with a non-space
/// character; the unit is everything before the first `' '`, so it is non-empty,
/// and `splitn` always yields a first element. Two guards said otherwise — a
/// `"missing unit"` behind `ok_or_else` and an `unit.is_empty()` disjunct — and
/// neither was reachable. They went when the failures were enumerated; a
/// variant nothing constructs is a claim this module cannot back.
pub fn parse_content_range(s: &str) -> Result<ContentRange, ContentRangeDefect<'_>> {
    let s = s.trim();
    if s.is_empty() {
        return Err(ContentRangeDefect::Empty);
    }

    // Expect unit SP range-resp / unsatisfied-range
    let mut parts = s.splitn(2, ' ');
    let unit = parts
        .next()
        .expect("splitn always yields at least one element");

    // A unit this parser does not model is not a malformed unit. Range units are a
    // token and an open set, so the only thing checkable here is that the name is
    // well-formed; deciding whether `bytes` semantics may be applied to it belongs
    // to the caller, which is the only party that knows what it is about to do with
    // the answer.
    //
    // cite(RFC 9110 § 14.1): "All range unit names are case-insensitive and ought to be registered within the "HTTP Range Unit Registry", as defined in Section 16.5.1."
    // cite(RFC 9110 § 14.1): "Range units are intended to be extensible, as described in Section 16.5."
    if crate::helpers::token::find_invalid_token_char(unit).is_some() {
        return Err(ContentRangeDefect::Unit(unit));
    }
    let lowercased_unit = unit.to_ascii_lowercase();
    let rest = parts.next().ok_or(ContentRangeDefect::MissingRangeResp)?;

    // The production holds exactly one space, the SP after the range-unit, and
    // neither alternative after it admits another: no OWS sits beside the "/",
    // the "-" or the digits. This parser used to trim around every separator it
    // found, so `bytes 0-499 / 1234` and `bytes  0-499/1234` both parsed -- values
    // no sender may generate, accepted in silence by the only rule that reads this
    // field. Trimming the value as a whole stays: leading and trailing whitespace
    // is not part of a field value at all, which is a different sentence.
    //
    // cite(RFC 9110 § 14.4, label: Content-Range grammar): "Content-Range = range-unit SP ( range-resp / unsatisfied-range )"
    // cite(RFC 9110 § 5.5): "A field value does not include leading or trailing whitespace."
    if rest.chars().any(|c| c.is_ascii_whitespace()) {
        return Err(ContentRangeDefect::WhitespaceInRangeResp(rest));
    }

    let slash_idx = rest.find('/').ok_or(ContentRangeDefect::MissingSlash)?;
    let left = &rest[..slash_idx];
    let right = &rest[slash_idx + 1..];

    // The "*" is not a wildcard standing in for the range here -- it is the first
    // character of a two-character literal, which is why nothing but an exact "*"
    // is accepted before the "/", and why the complete-length after it may not
    // itself be "*". A 416 always knows how long the representation is.
    //
    // cite(RFC 9110 § 14.4): "unsatisfied-range = "*/" complete-length"
    if !left.is_empty() && left.starts_with('*') {
        // Left "*" should be exact
        if left != "*" {
            return Err(ContentRangeDefect::ValueBeforeSlash);
        }
        // Right must be a number (complete-length)
        // cite(RFC 9110 § 14.4): "complete-length = 1*DIGIT"
        let instance_length = parse_u128(right, Numeral::CompleteLength)?;
        return Ok(ContentRange::Unsatisfiable {
            unit: lowercased_unit,
            instance_length,
        });
    }

    // Otherwise expect first-last
    // cite(RFC 9110 § 14.4): "range-resp = incl-range "/" ( complete-length / "*" )"
    // cite(RFC 9110 § 14.4): "incl-range = first-pos "-" last-pos"
    let dash_idx = left.find('-').ok_or(ContentRangeDefect::MissingDash)?;
    let first = &left[..dash_idx];
    let last = &left[dash_idx + 1..];

    if first.is_empty() || last.is_empty() {
        return Err(ContentRangeDefect::MissingPosition);
    }

    let first_v = parse_u128(first, Numeral::FirstPos)?;
    let last_v = parse_u128(last, Numeral::LastPos)?;
    // The first of the sentence's two invalidity conditions. It is also what makes
    // `last - first` safe for callers, who are otherwise one unsigned subtraction
    // away from an underflow.
    //
    // cite(RFC 9110 § 14.4): "A Content-Range field value is invalid if it contains a range-resp that has a last-pos value less than its first-pos value, or a complete-length value less than or equal to its last-pos value."
    if first_v > last_v {
        return Err(ContentRangeDefect::FirstPosAfterLastPos);
    }

    let instance_length = if right == "*" {
        None
    } else {
        Some(parse_u128(right, Numeral::CompleteLength)?)
    };

    // The second condition of the same sentence. "Less than or equal to" is the
    // exact reach: positions are zero-based and inclusive, so a last-pos of 499
    // needs a complete-length of 500 to be the last byte rather than one past the
    // end. `*` asserts nothing about length and so cannot contradict last-pos.
    //
    // cite(RFC 9110 § 14.4): "A Content-Range field value is invalid if it contains a range-resp that has a last-pos value less than its first-pos value, or a complete-length value less than or equal to its last-pos value."
    if let Some(len) = instance_length {
        if len <= last_v {
            return Err(ContentRangeDefect::CompleteLengthNotAfterLastPos {
                length: len,
                last: last_v,
            });
        }
    }

    Ok(ContentRange::Satisfied {
        unit: lowercased_unit,
        first: first_v,
        last: last_v,
        instance_length,
    })
}

/// The three numeric fields of this header are each `1*DIGIT`, which is digits
/// and nothing else. Rust's integer parser is more generous than that: it accepts
/// a leading `+`, so `bytes +0-499/1234` used to parse as the range 0-499 -- a
/// value outside the grammar, read as though it were inside it.
///
/// The `u128` ceiling is a tolerance rather than a quoted requirement, and it is
/// left in place with its reason: § 14.1.2 tells recipients to anticipate large
/// numerals and not to fail on integer conversion overflow, which this satisfies
/// by returning an error instead of wrapping. A position that no recipient can
/// represent cannot address the octets of any representation either. It takes a
/// 39-digit numeral to reach, and the same bound is argued the same way in
/// `validate_content_length`.
///
/// The `numeral` argument is which of the three this is, and it is taken rather
/// than fixed up afterwards because the caller is the only one that knows.
/// Overflow is the only way `str::parse` can fail once the digits are checked,
/// which is why it maps to a variant of its own rather than to the parser's
/// sentence: the `ParseIntError` text this used to embed said "number too large
/// to fit in target type", naming Rust's type in a finding about HTTP.
///
// cite(RFC 9110 § 14.4): "complete-length = 1*DIGIT"
// cite(RFC 9110 § 14.1.2): "In the byte-range syntax, first-pos, last-pos, and suffix-length are expressed as decimal number of octets.  Since there is no predefined limit to the length of content, recipients MUST anticipate potentially large decimal numerals and prevent parsing errors due to integer conversion overflows."
fn parse_u128(s: &str, numeral: Numeral) -> Result<u128, ContentRangeDefect<'_>> {
    if s.is_empty() || !s.chars().all(|c| c.is_ascii_digit()) {
        return Err(ContentRangeDefect::NotDigits { numeral, value: s });
    }
    s.parse::<u128>()
        .map_err(|_| ContentRangeDefect::TooLarge { numeral, value: s })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_satisfied() {
        let v = parse_content_range("bytes 0-499/1234").unwrap();
        assert_eq!(
            v,
            ContentRange::Satisfied {
                unit: "bytes".into(),
                first: 0,
                last: 499,
                instance_length: Some(1234)
            }
        );

        let v2 = parse_content_range("bytes 5-5/*").unwrap();
        assert_eq!(
            v2,
            ContentRange::Satisfied {
                unit: "bytes".into(),
                first: 5,
                last: 5,
                instance_length: None
            }
        );

        // A value whose only defect is the whitespace around its separators is
        // still a value no sender may generate. This assertion used to say the
        // opposite, which is how the leniency stayed. The SP the production
        // holds is the one after `bytes`; everything after it is the part the
        // defect names.
        assert_eq!(
            parse_content_range("bytes  0-0 /  *"),
            Err(ContentRangeDefect::WhitespaceInRangeResp(" 0-0 /  *"))
        );

        // Whitespace *around the field value* is not part of it, so it is trimmed
        // rather than reported.
        assert_eq!(
            parse_content_range("  bytes 0-0/*  ").unwrap(),
            ContentRange::Satisfied {
                unit: "bytes".into(),
                first: 0,
                last: 0,
                instance_length: None
            }
        );
    }

    /// `1*DIGIT` is digits and nothing else; Rust's integer parser also takes a
    /// leading "+", which would have read `+0-499` as the range 0-499.
    ///
    /// Each numeral names itself now, which is what the four assertions were
    /// always about and could not say: `is_err()` passed whichever of the three
    /// had rejected the value.
    #[test]
    fn signed_positions_are_not_digits() {
        let not_digits = |numeral, value| Err(ContentRangeDefect::NotDigits { numeral, value });
        assert_eq!(
            parse_content_range("bytes +0-499/1234"),
            not_digits(Numeral::FirstPos, "+0")
        );
        assert_eq!(
            parse_content_range("bytes 0-+499/1234"),
            not_digits(Numeral::LastPos, "+499")
        );
        assert_eq!(
            parse_content_range("bytes 0-499/+1234"),
            not_digits(Numeral::CompleteLength, "+1234")
        );
        assert_eq!(
            parse_content_range("bytes */+1234"),
            not_digits(Numeral::CompleteLength, "+1234")
        );
    }

    /// The ceiling is a tolerance and reports as one. § 14.1.2 asks recipients
    /// to anticipate large numerals rather than overflow on them; what a reader
    /// used to get here was `ParseIntError`'s "number too large to fit in
    /// target type", which names a Rust type in a finding about HTTP.
    #[test]
    fn a_numeral_past_the_ceiling_names_itself_and_not_a_rust_type() {
        let past = "340282366920938463463374607431768211456"; // u128::MAX + 1
        let value = format!("bytes 0-1/{past}");
        assert_eq!(
            parse_content_range(&value),
            Err(ContentRangeDefect::TooLarge {
                numeral: Numeral::CompleteLength,
                value: past,
            })
        );
        assert_eq!(
            parse_content_range(&value).unwrap_err().message(),
            format!("invalid complete-length: '{past}' is larger than this parser can represent")
        );
    }

    #[test]
    fn parse_valid_unsatisfiable() {
        let v = parse_content_range("bytes */1234").unwrap();
        assert_eq!(
            v,
            ContentRange::Unsatisfiable {
                unit: "bytes".into(),
                instance_length: 1234
            }
        );
    }

    /// A range unit this parser does not model is still a legal range unit:
    /// `range-unit = token`, and the set is extensible. Parsing it is not the
    /// same as agreeing to apply byte semantics to it -- that is the caller's
    /// call, and `range_and_content_range_consistent` makes it.
    #[test]
    fn unmodelled_unit_parses_and_is_reported() {
        let v = parse_content_range("items 0-1/3").unwrap();
        assert_eq!(
            v,
            ContentRange::Satisfied {
                unit: "items".into(),
                first: 0,
                last: 1,
                instance_length: Some(3)
            }
        );
        // The generic validity conditions still apply to it, and they are the
        // two that are prose rather than grammar.
        assert_eq!(
            parse_content_range("items 1-0/3"),
            Err(ContentRangeDefect::FirstPosAfterLastPos)
        );
        assert_eq!(
            parse_content_range("items 0-5/3"),
            Err(ContentRangeDefect::CompleteLengthNotAfterLastPos { length: 3, last: 5 })
        );
    }

    #[test]
    fn unit_names_are_case_insensitive() {
        assert_eq!(parse_content_range("BYTES 0-1/3").unwrap().unit(), "bytes");
    }

    /// The second value is the one worth naming: it has no unit *missing*, it
    /// has a unit of `0-1/3`, because the field value's own whitespace comes
    /// off before anything is read. A value cannot reach here without a unit,
    /// which is why there is no variant for one.
    #[test]
    fn invalid_unit() {
        // Not a token: "(" is not a tchar.
        assert_eq!(
            parse_content_range("by(tes 0-1/3"),
            Err(ContentRangeDefect::Unit("by(tes"))
        );
        assert_eq!(
            parse_content_range(" 0-1/3"),
            Err(ContentRangeDefect::Unit("0-1/3"))
        );
    }

    /// Five malformed values that `is_err()` could not tell apart, and which
    /// fail at five different points of the value.
    #[test]
    fn malformed_values() {
        assert_eq!(
            parse_content_range("bytes 5-3/10"),
            Err(ContentRangeDefect::FirstPosAfterLastPos)
        );
        assert_eq!(
            parse_content_range("bytes 5- /10"),
            Err(ContentRangeDefect::WhitespaceInRangeResp("5- /10"))
        );
        assert_eq!(
            parse_content_range("bytes -5/10"),
            Err(ContentRangeDefect::MissingPosition)
        );
        assert_eq!(
            parse_content_range("bytes */*"),
            Err(ContentRangeDefect::NotDigits {
                numeral: Numeral::CompleteLength,
                value: "*"
            })
        );
        assert_eq!(
            parse_content_range("bytes */x"),
            Err(ContentRangeDefect::NotDigits {
                numeral: Numeral::CompleteLength,
                value: "x"
            })
        );
        // The two the list did not reach: a unit and nothing after it, and a
        // range-resp with no "/" to divide it.
        assert_eq!(
            parse_content_range("bytes"),
            Err(ContentRangeDefect::MissingRangeResp)
        );
        assert_eq!(
            parse_content_range("bytes 0-1"),
            Err(ContentRangeDefect::MissingSlash)
        );
        assert_eq!(
            parse_content_range("bytes 01/3"),
            Err(ContentRangeDefect::MissingDash)
        );
        assert_eq!(parse_content_range("   "), Err(ContentRangeDefect::Empty));
    }

    /// The examples § 14.4 states in its own prose, all of which describe a
    /// representation of 1234 bytes.
    #[test]
    fn section_14_4_examples_are_valid() {
        for v in [
            "bytes 42-1233/1234",
            "bytes 42-1233/*",
            "bytes 0-499/1234",
            "bytes 500-999/1234",
            "bytes 500-1233/1234",
            "bytes 734-1233/1234",
            "bytes */1234",
        ] {
            assert!(parse_content_range(v).is_ok(), "{v} should parse");
        }
    }

    #[test]
    fn complete_length_must_exceed_last_pos() {
        // last-pos 499 needs at least 500 bytes to exist.
        assert!(parse_content_range("bytes 0-499/500").is_ok());
        assert_eq!(
            parse_content_range("bytes 0-499/499"),
            Err(ContentRangeDefect::CompleteLengthNotAfterLastPos {
                length: 499,
                last: 499
            })
        );
        assert_eq!(
            parse_content_range("bytes 0-499/10"),
            Err(ContentRangeDefect::CompleteLengthNotAfterLastPos {
                length: 10,
                last: 499
            })
        );
        // Unknown complete length says nothing about last-pos.
        assert!(parse_content_range("bytes 0-499/*").is_ok());
    }

    #[test]
    fn ranges_specifier_splits_at_the_first_equals() {
        assert_eq!(
            split_ranges_specifier("bytes=0-499"),
            Some(("bytes".into(), "0-499"))
        );
        assert_eq!(
            split_ranges_specifier(" BYTES = 0-1, 5-9 "),
            Some(("bytes".into(), "0-1, 5-9"))
        );
        // `other-range` admits "=" (%x3D is inside %x2D-7E); `range-unit` is a
        // token and cannot, so the first "=" is always the separator.
        assert_eq!(
            split_ranges_specifier("pages=a=b"),
            Some(("pages".into(), "a=b"))
        );
    }

    #[test]
    fn ranges_specifier_rejects_non_specifiers() {
        assert_eq!(split_ranges_specifier("bytes 0-499"), None);
        assert_eq!(split_ranges_specifier("=0-499"), None);
        assert_eq!(split_ranges_specifier("by(tes=0-499"), None);
    }

    #[test]
    fn unexpected_star_prefix_reports_error() {
        assert_eq!(
            parse_content_range("bytes *1/1234"),
            Err(ContentRangeDefect::ValueBeforeSlash)
        );
    }
}
