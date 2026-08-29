// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `( token / quoted-string )`, and reading one out of a list member.
//!
//! **The alternation has no name in the document in force**, and the module's
//! does not come from it. RFC 7230 § 3.2.6 called it `word`; RFC 9110 dropped
//! the name and writes the two halves out at each field that needs them —
//! `parameter-value`, `auth-param`'s right-hand side, `cache-directive`'s
//! argument. The short name is kept here because the construct is one thing and
//! seven callers read it, and the citation below points at the place RFC 9110
//! prints it as a production of its own.
//!
//! It was nearly filed under `token`, which would have been wrong in a way
//! worth recording: [`token_or_quoted_string`] transcribes *both* alternatives
//! and cites both, so shelving it beside the `token` character set would have
//! named it for half its own grammar.
//!
//! [`WordDefect`] is the typed defect. Its `Empty` variant is arithmetic on the
//! two alternatives rather than a per-field rule — `token = 1*tchar` has a
//! one-character floor and the shortest `quoted-string` is its two DQUOTEs — so
//! no value derives the empty string, and what a *field* does about that is
//! still the field's own question.
//!
// cite(RFC 9110 § 5.6.6): "parameter-value = ( token / quoted-string )"

use crate::helpers::headers::trim_ows;
use crate::helpers::quoted_string::unescape_quoted_string;
use crate::helpers::shown::describe_char;

/// Why a value derives from neither alternative of `( token / quoted-string )`.
///
/// Data rather than a sentence, and that is the whole reason this extraction was
/// possible at all. The alternation is one production; the finding is not. Seven
/// sites read this pair and each says something about its own field — an
/// `Alt-Svc` parameter, a `Server-Timing` parameter, a `Pragma` directive, a
/// media type's parameter, a `Keep-Alive` parameter, a `Prefer` preference. Six
/// of them had also decided, separately and in four different ways, what an
/// empty value means. So what is shared here is the decision and the two
/// measurements behind it; **the wording, and the verdict on
/// [`WordDefect::Empty`], stay at the caller** — which is where each field's own
/// sentence about it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WordDefect {
    /// The value is empty, and neither alternative derives the empty string:
    /// `token = 1*tchar` has a one-character floor, and the shortest
    /// `quoted-string` is its two DQUOTEs. That is arithmetic on two
    /// productions and is not a per-field question — but what a field *does*
    /// about it is, and two rules in this tree tolerate it on the record.
    Empty,
    /// An unquoted value holding a character no `tchar` admits. Unquoted by
    /// elimination rather than by inspection: see [`token_or_quoted_string`].
    NotToken(char),
    /// A leading DQUOTE opened something that is not a well-formed
    /// `quoted-string`, carrying the interior walk's own account of it.
    NotQuotedString(String),
}

/// Read one `( token / quoted-string )` and return what it holds.
///
/// The alternation is decided by the first octet and by nothing else: RFC 9110
/// § 5.6.2 makes DQUOTE a delimiter, so no `token` can open with one and a value
/// that does is trying to be a `quoted-string` and nothing else. A value that
/// does not open with one is a `token` by elimination, which is why the `tchar`
/// scan below is the whole of that half.
///
/// The content returned is what the field means by the value: a `token` as
/// written, a `quoted-string` after `quoted-pair` substitution. A caller that
/// only judges the value may discard it — [`unescape_quoted_string`] opens by
/// asking [`validate_quoted_string`](crate::helpers::quoted_string::validate_quoted_string), so the two accept exactly the same strings
/// and the `Err` is the same `Err`.
///
/// RFC 7230 named this pair `word`; RFC 9110 kept both halves and dropped the
/// name, which is why the two productions cited here are the halves and not the
/// whole. Callers whose own document writes its own name for it —
/// `server-timing-param-value`, `parameter-value`, RFC 2068's `value` — cite
/// that at their site.
///
// cite(RFC 9110 § 5.6.2): "Delimiters are chosen from the set of US-ASCII visual characters not allowed in a token (DQUOTE and "(),/:;<=>?@[\]{}")."
// cite(RFC 9110 § 5.6.2): "token = 1*tchar tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA"
// cite(RFC 9110 § 5.6.4): "quoted-string  = DQUOTE *( qdtext / quoted-pair ) DQUOTE"
pub fn token_or_quoted_string(value: &str) -> Result<std::borrow::Cow<'_, str>, WordDefect> {
    if value.is_empty() {
        return Err(WordDefect::Empty);
    }
    if value.starts_with('"') {
        return unescape_quoted_string(value)
            .map(std::borrow::Cow::Owned)
            .map_err(WordDefect::NotQuotedString);
    }
    match crate::helpers::token::find_invalid_token_char(value) {
        Some(c) => Err(WordDefect::NotToken(c)),
        None => Ok(std::borrow::Cow::Borrowed(value)),
    }
}

/// One `token [ BWS "=" BWS word ]` pair, parsed.
///
/// RFC 7240 writes that production three times — `preference`, `parameter` and
/// `applied-pref` — and says in prose that the third is the first minus its
/// parameters, so the pair itself is one thing written once here rather than
/// per field. `word` is the name RFC 7230 gave `( token / quoted-string )`;
/// RFC 9110 kept both halves and dropped the name, which is why the pair is
/// cited by its halves at [`token_or_quoted_string`], where it is read, and not
/// under a name no document in force writes.
pub struct TokenBwsWord<'a> {
    /// The `token`, exactly as written. Case folding is the caller's: whether
    /// two names are the same string is a question each field answers for
    /// itself.
    pub name: &'a str,
    /// The `word`'s content — `None` when the optional group is absent, and for
    /// a `quoted-string` the octets after `quoted-pair` substitution rather than
    /// the quoted form. An empty `Some` can only come from `""`, which some
    /// fields define as meaning no value; that reading belongs to the field, so
    /// it is reported here as what was written.
    pub value: Option<String>,
    /// Whether whitespace appeared beside the `=`.
    ///
    /// The member handed in has already lost the `OWS` its list prints around
    /// the commas, so anything still adjacent to the `=` is the `BWS` the
    /// grammar admits only for historical reasons — and that is a statement
    /// about the sender, which is why this is returned instead of being
    /// silently absorbed by the trim that has to happen anyway.
    pub bws: bool,
}

/// Parse `token [ BWS "=" BWS word ]` from one already-`OWS`-trimmed member.
///
/// Callers reading a field through [`combined_field_value_as_written`](crate::helpers::headers::combined_field_value_as_written) hand this
/// one `char` per octet, and that is the intended input: an `obs-text` octet is
/// admitted by the `quoted-string` half and by no part of the `token` half, so
/// only the octets say which side of the alternation it landed on.
///
/// The shape itself is cited at the field that has it, not here — a helper
/// shared by three productions can honestly quote only the halves they agree
/// on. `token` is transcribed once at [`crate::helpers::token::is_tchar`], and
/// the `word` half is read by [`token_or_quoted_string`]; what is left here is
/// the part RFC 7240 owns, which is the optional group and the `BWS`.
///
/// cite(RFC 9110 § 5.6.3): "The BWS rule is used where the grammar allows optional whitespace only for historical reasons."
pub fn parse_token_bws_word(member: &str) -> Result<TokenBwsWord<'_>, String> {
    // `token` admits neither `=` nor DQUOTE, so nothing can precede the `=` the
    // production prints except the name -- there is no quoted-string in front of
    // it for one to hide in, and the first `=` is therefore the delimiter even
    // when the `word` after it is a quoted-string containing more of them.
    let (name_written, value_written) = match member.find('=') {
        Some(i) => (&member[..i], Some(&member[i + 1..])),
        None => (member, None),
    };
    let name = trim_ows(name_written);
    let value_written_trimmed = value_written.map(trim_ows);
    let bws = name != name_written || value_written_trimmed != value_written;

    if name.is_empty() {
        return Err("no token before the \"=\"".to_string());
    }
    if let Some(c) = crate::helpers::token::find_invalid_token_char(name) {
        return Err(format!("token contains {}", describe_char(c)));
    }

    let value = match value_written_trimmed {
        None => None,
        Some(v) => match token_or_quoted_string(v) {
            Ok(content) => Some(content.into_owned()),
            // `word` is `token / quoted-string` and `token` is `1*tchar`, so the
            // optional group cannot close on an empty value: a field that means
            // to say "no value" writes no `=`, or writes `""`. RFC 7240 grants
            // no tolerance for the third spelling, so this is a defect here.
            Err(WordDefect::Empty) => {
                return Err("nothing after the \"=\", where the grammar has a word".to_string())
            }
            Err(WordDefect::NotToken(c)) => {
                return Err(format!("value contains {}", describe_char(c)))
            }
            Err(WordDefect::NotQuotedString(e)) => return Err(e),
        },
    };

    Ok(TokenBwsWord { name, value, bws })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The alternation is decided by the first octet and by nothing else, and
    /// each of the three defects is a distinct answer rather than one `Err`:
    /// the seven callers that used to write this out disagree about `Empty` in
    /// particular, so it has to arrive as something they can match on.
    #[test]
    fn token_or_quoted_string_separates_its_three_defects() {
        assert_eq!(token_or_quoted_string("abc").unwrap(), "abc");
        // The content is what the field means by the value, so the DQUOTEs come
        // off and a `quoted-pair` is substituted.
        assert_eq!(token_or_quoted_string("\"a\\\"b\"").unwrap(), "a\"b");
        // `""` is two DQUOTEs and derives from the production; its content is
        // empty, which is not the same fact as the value being empty.
        assert_eq!(token_or_quoted_string("\"\"").unwrap(), "");

        assert_eq!(token_or_quoted_string(""), Err(WordDefect::Empty));
        assert_eq!(
            token_or_quoted_string("a b"),
            Err(WordDefect::NotToken(' '))
        );
        // A leading DQUOTE commits the value to the `quoted-string` half: RFC
        // 9110 § 5.6.2 makes DQUOTE a delimiter, so this is not a `token`
        // holding a bad character, it is a malformed `quoted-string`.
        assert!(matches!(
            token_or_quoted_string("\"abc"),
            Err(WordDefect::NotQuotedString(_))
        ));
        assert!(matches!(
            token_or_quoted_string("\"abc\"x"),
            Err(WordDefect::NotQuotedString(_))
        ));
    }

    /// The reader is handed one `char` per octet by every caller that reads a
    /// field through [`combined_field_value_as_written`](crate::helpers::headers::combined_field_value_as_written), and the two halves
    /// answer an `obs-text` octet differently on purpose: `qdtext` admits it and
    /// `tchar` does not.
    #[test]
    fn obs_text_lands_on_the_side_of_the_alternation_the_grammar_puts_it() {
        let quoted: String = [b'"', 0xE9, b'"'].iter().map(|&b| b as char).collect();
        assert_eq!(
            token_or_quoted_string(&quoted).unwrap().chars().count(),
            1,
            "an obs-text octet is qdtext and comes back as one octet"
        );
        let bare: String = [0xE9u8].iter().map(|&b| b as char).collect();
        assert_eq!(
            token_or_quoted_string(&bare),
            Err(WordDefect::NotToken('\u{E9}'))
        );
    }
}
