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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    /// `quoted-string`, carrying that production's own defect.
    ///
    /// Nested rather than rendered, for the reason
    /// [`UriHostDefect::PercentEncoding`](crate::helpers::uri::UriHostDefect::PercentEncoding)
    /// nests its own: a `quoted-string` is the same production wherever it is
    /// read, and this alternation adds nothing to it. It carried a `String`
    /// while [`unescape_quoted_string`] rendered one, which put prose inside a
    /// typed defect and left every caller matching this variant unable to name
    /// *which* of the four ways the value failed.
    NotQuotedString(crate::helpers::quoted_string::QuotedStringDefect),
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

/// Why a member does not derive from `token [ BWS "=" BWS word ]`.
///
/// The two halves of the production answer separately, because they are two
/// productions: the name is a `token`, and what follows the `=` is a `word`,
/// whose own defects [`WordDefect`] already names. Nothing here is a fact about
/// the *pair* — which is why there is no fourth variant, and why the whole of
/// this type is a delegation.
///
/// It used to answer in a rendered `String`, which is what kept four rules
/// wording the same three verdicts about the same production. The messages are
/// unchanged: [`TokenBwsWordDefect::message`] renders exactly what the `Err`
/// arms rendered, at the site that has the member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenBwsWordDefect {
    /// Nothing before the `=`, where the production prints a `token`.
    NameEmpty,
    /// The name holds an octet no `tchar` admits.
    NameCharacter(char),
    /// The `word` after the `=`.
    Value(WordDefect),
}

impl TokenBwsWordDefect {
    /// The finding's words, given the member they were read from.
    ///
    /// The member rather than the value, because the caller has the member —
    /// it is what it handed in — and the `quoted-string` half needs the text it
    /// failed to unquote. Splitting it again here is cheaper than threading a
    /// second argument through four rules, and it is the same split the parse
    /// made.
    pub fn message(&self, member: &str) -> String {
        match self {
            Self::NameEmpty => "no token before the \"=\"".to_string(),
            Self::NameCharacter(c) => format!("token contains {}", describe_char(*c)),
            Self::Value(WordDefect::Empty) => {
                "nothing after the \"=\", where the grammar has a word".to_string()
            }
            Self::Value(WordDefect::NotToken(c)) => {
                format!("value contains {}", describe_char(*c))
            }
            Self::Value(WordDefect::NotQuotedString(defect)) => {
                defect.message(written_value(member).unwrap_or(""))
            }
        }
    }
}

/// The text after the first `=`, `OWS`-trimmed — the half the `word`
/// alternation is read from.
///
/// `token` admits neither `=` nor DQUOTE, so nothing can precede the `=` the
/// production prints except the name: there is no quoted-string in front of it
/// for one to hide in, and the first `=` is therefore the delimiter even when
/// the `word` after it is a quoted-string containing more of them.
fn written_value(member: &str) -> Option<&str> {
    member.find('=').map(|i| trim_ows(&member[i + 1..]))
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
pub fn parse_token_bws_word(member: &str) -> Result<TokenBwsWord<'_>, TokenBwsWordDefect> {
    let (name_written, value_written) = match member.find('=') {
        Some(i) => (&member[..i], Some(&member[i + 1..])),
        None => (member, None),
    };
    let name = trim_ows(name_written);
    let value_written_trimmed = value_written.map(trim_ows);
    let bws = name != name_written || value_written_trimmed != value_written;

    if name.is_empty() {
        return Err(TokenBwsWordDefect::NameEmpty);
    }
    if let Some(c) = crate::helpers::token::find_invalid_token_char(name) {
        return Err(TokenBwsWordDefect::NameCharacter(c));
    }

    let value = match value_written_trimmed {
        None => None,
        Some(v) => match token_or_quoted_string(v) {
            Ok(content) => Some(content.into_owned()),
            // `word` is `token / quoted-string` and `token` is `1*tchar`, so the
            // optional group cannot close on an empty value: a field that means
            // to say "no value" writes no `=`, or writes `""`. RFC 7240 grants
            // no tolerance for the third spelling, so this is a defect here.
            Err(defect) => return Err(TokenBwsWordDefect::Value(defect)),
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

    /// The four verdicts the pair can reach, and the words each of them keeps.
    ///
    /// Written against the parse rather than against the variants, because what
    /// typing this changed is that a caller can now ask *which* defect it has
    /// while rendering the same sentence it always rendered — and the sentences
    /// are what four rules' message assertions are written on.
    #[test]
    fn the_pair_answers_with_the_half_that_failed_and_says_the_same_words() {
        let defect = |member: &str| {
            let Err(defect) = parse_token_bws_word(member) else {
                panic!("{member} derives from the production")
            };
            let message = defect.message(member);
            (defect, message)
        };

        let (d, m) = defect("=x");
        assert_eq!(d, TokenBwsWordDefect::NameEmpty);
        assert_eq!(m, "no token before the \"=\"");

        let (d, m) = defect("a@b=x");
        assert_eq!(d, TokenBwsWordDefect::NameCharacter('@'));
        assert_eq!(m, "token contains '@'");

        let (d, m) = defect("foo=");
        assert_eq!(d, TokenBwsWordDefect::Value(WordDefect::Empty));
        assert_eq!(m, "nothing after the \"=\", where the grammar has a word");

        let (d, m) = defect("foo=a b");
        assert_eq!(d, TokenBwsWordDefect::Value(WordDefect::NotToken(' ')));
        assert_eq!(m, "value contains ' '");

        // The quoted half needs the text it failed to unquote, and the message
        // is the `quoted-string` subject's rather than this one's — which is
        // the whole reason `message` takes the member back.
        let (d, m) = defect("foo=\"abc");
        assert!(matches!(
            d,
            TokenBwsWordDefect::Value(WordDefect::NotQuotedString(_))
        ));
        assert!(m.contains("abc"), "{m}");
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
