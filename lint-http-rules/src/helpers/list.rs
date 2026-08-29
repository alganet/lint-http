// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Where a list's members begin and end.
//!
//! The `#rule` — `1#element => element *( OWS "," OWS element )` — and the
//! semicolon-separated forms beside it. [`split_top_level`] is the one walk; the
//! comma and semicolon splitters name which separator they mean, and
//! [`list_members_as_written`] names what the slices are. That walk was once
//! written out twice, identical but for the byte compared, which is the shape
//! that lets a fix to one be a silent non-fix in the other.
//!
//! **Every segment comes back with its `OWS` removed, and by [`trim_ows`] rather
//! than `str::trim`.** `str::trim` is Unicode whitespace, and a value read
//! through `combined_field_value_as_written` carries one `char` per octet — so
//! %xA0 and %x85, the two `obs-text` octets that most look like a space, were
//! being stripped from a member's ends before any check could see them, and
//! `obs-text` is exactly the class no `token` admits.
//!
//! **The escape rule here is deliberately not `quoted-string`'s.** These walks
//! track quote parity so a `,` inside a `quoted-string` does not end a member,
//! but they do not honour a backslash at top level: `quoted-pair` is defined as
//! part of `quoted-string` and nowhere else, and honouring it out here let a
//! stray backslash suppress the DQUOTE after it, flipping parity for the rest of
//! the value and swallowing every later member into one segment.
//! [`crate::helpers::quoted_string`] owns the production; this module owns the
//! boundary.
//!
//! [`quoting_is_balanced`] is the gate for a rule whose finding is that a member
//! is *absent* — when the quoting never closes, no separator past the stray
//! DQUOTE is a separator, and "missing" would really mean "unreadable". It lives
//! here because it has to agree with the splitters about what a quote is.
//!
// cite(RFC 9110 § 5.6.1.1): "1#element => element *( OWS "," OWS element )"
// cite(RFC 9110 § 5.6.3, label: OWS grammar): "OWS            = *( SP / HTAB )"

use crate::helpers::headers::trim_ows;

/// Every member of a `#element` list, `OWS`-trimmed, with the empty ones dropped.
///
/// A recipient's reader, and "dropping the empty ones" is what makes it one. `a,,b`
/// is a two-element list and not a malformed one; a *sender* must not generate the
/// empty element (§ 5.6.1.1), which is a different rule for a different party — so
/// a rule wanting to flag `a,,b` as bad output cannot ask this function, because by
/// the time it answers, the evidence is gone. [`list_members_as_written`] is the
/// walk that keeps it.
///
/// § 5.6.1.2 bounds the ignoring — "a reasonable number", but not so many that it
/// becomes a denial-of-service vector — and this imposes no cap. That is deliberate
/// rather than overlooked: the bound protects a recipient from the cost of the
/// ignoring, and `split` + `filter` is linear with no amplification. There is
/// nothing here to exhaust.
///
/// **The trim is `OWS` and not `str::trim`, and this was two functions until it
/// was read.** Four decisions make up a `#rule` walk — where to split, what to
/// trim, whether to drop an empty element, and whether to fold case — and
/// `parse_list_header` differed from this one in exactly the second: `OWS` is
/// `*( SP / HTAB )`, and `str::trim` removes every character `char::is_whitespace`
/// admits. That difference cannot show on a value read back through
/// `HeaderValue::to_str`, which returns `Err` for every octet outside `%x20-7E`
/// plus HTAB — so the `&str` it hands back holds no other whitespace character to
/// trim. It shows on the two readers that do not go through it, and it shows
/// differently on each.
///
/// [`combined_field_value_as_written`](crate::helpers::headers::combined_field_value_as_written) and [`field_line_as_written`](crate::helpers::headers::field_line_as_written) carry one
/// `char` per octet, so the disagreement is exactly two characters wide: U+00A0
/// and U+0085, which are the octets %xA0 and %x85. Both are `obs-text` a sender
/// wrote *inside* a member — the very octet class no `token` admits — and
/// trimming either hands the member's own grammar a value the sender did not
/// write.
///
/// It used to be wider, because some callers read their value with
/// `String::from_utf8_lossy`, which decodes the octets as UTF-8 and so admits
/// every whitespace `char` there is — U+2003, U+3000, U+1680, U+2028. No caller
/// does that now; the reason it was wrong for more than the trim is written at
/// [`field_line_as_written`](crate::helpers::headers::field_line_as_written).
///
/// The split is naive: a DQUOTE is not read as opening a `quoted-string`. That is
/// the grammar's answer where the element admits none, and the wrong one where it
/// does; [`list_members_as_written`] is the quote-aware walk and says which is
/// which at its own doc comment.
///
// cite(RFC 9110 § 5.6.1.2): "#element => [ element ] *( OWS "," OWS [ element ] )"
// cite(RFC 9110 § 5.6.1.2): "Empty elements do not contribute to the count of elements present."
// cite(RFC 9110 § 5.6.1.2): "A recipient MUST parse and ignore a reasonable number of empty list elements:"
// cite(RFC 9110 § 5.6.1.1): "In any production that uses the list construct, a sender MUST NOT generate empty list elements."
// cite(RFC 9110 § 5.6.3, label: OWS grammar): "OWS            = *( SP / HTAB )"
pub fn list_members(val: &str) -> impl Iterator<Item = &str> {
    val.split(',').map(trim_ows).filter(|s| !s.is_empty())
}

/// The sender's members of a list whose element admits no `quoted-string`:
/// cut at every comma, `OWS`-trimmed, empty members preserved.
///
/// **The fourth cell of a walk this module already held two cells of.** A walk
/// over a `#rule` decides two things separately: whether a DQUOTE opens a
/// `quoted-string`, and whether an empty member survives.
/// [`list_members_as_written`] is quote-aware and empty-preserving;
/// [`list_members`] is naive and empty-dropping; this is naive *and*
/// preserving, and both halves are decisions rather than shortcuts.
///
/// **Naive**, because the caller's element admits no `quoted-string` anywhere
/// inside it — a DQUOTE there is a character the member may not hold, and
/// reading it as opening a string would make the next comma data when there is
/// nothing for it to be data in. The delimiters sentence is why the comma is
/// safe to cut at: `,` is one of the characters chosen *because* no `token`
/// holds it.
///
/// **Empty-preserving**, because dropping the empty member is § 5.6.1.2's
/// instruction to a *recipient*, and the callers here measure the *sender* —
/// § 5.6.1.1's MUST NOT is exactly about the member that instruction would
/// erase. Each caller decides for itself what an empty member means in its
/// field and reports it in its own words; what is shared is the walk, not the
/// verdict.
///
/// This body is two calls, and the extraction is for the name and the
/// paragraph above it: five rules wrote the walk out inline, three of them
/// with this same reasoning beside it, and a reader meeting `split(',')` in a
/// rule could not tell a decision from an accident.
// cite(RFC 9110 § 5.6.2): "Delimiters are chosen from the set of US-ASCII visual characters not allowed in a token (DQUOTE and "(),/:;<=>?@[\]{}")."
// cite(RFC 9110 § 5.6.1.2): "A recipient MUST parse and ignore a reasonable number of empty list elements:"
// cite(RFC 9110 § 5.6.1.1): "In any production that uses the list construct, a sender MUST NOT generate empty list elements."
// cite(RFC 9110 § 5.6.3, label: OWS grammar): "OWS            = *( SP / HTAB )"
pub fn sender_list_members(val: &str) -> impl Iterator<Item = &str> {
    val.split(',').map(trim_ows)
}

/// Parse a semicolon-separated list of directive values.
///
/// This iterator splits by semicolon, trims whitespace, and skips empty parts.
/// IMPORTANT: This is a *naive* splitter that simply calls `split(';')` and does
/// NOT respect quoted-strings. Do NOT use this helper for header parameter
/// parsing where quoted-string values may themselves contain semicolons
/// (for example, `Content-Disposition` parameters). For quote-aware splitting,
/// use `split_semicolons_respecting_quotes` which understands DQUOTE quoting and
/// backslash escapes.
///
/// Use `parse_semicolon_list` only for simple cases where you are certain
/// values cannot include quoted semicolons.
pub fn parse_semicolon_list(val: &str) -> impl Iterator<Item = &str> {
    val.split(';').map(|s| s.trim()).filter(|s| !s.is_empty())
}

/// Every member of a `#element` list, `OWS`-trimmed, **with the empty ones
/// kept**.
///
/// The second `#rule` walk in this module, and the axis it differs on is the one
/// that makes it a *sender's* reader rather than a recipient's.
/// [`list_members`] drops an empty member, because § 5.6.1.2 has a recipient
/// parse and ignore one — so by the time it answers, the evidence is gone. A
/// rule measuring what a sender wrote needs the
/// empty member *in the list*, since § 5.6.1.1 forbids generating it and
/// § 5.6.1.2's worked example makes a value of nothing but commas the invalid
/// spelling of a `1#` floor. Neither of those two findings can be made from a
/// list that has already dropped them.
///
/// It is also the only one of the two that is quote-aware. A comma inside a
/// `quoted-string` is `qdtext` and not a separator, so a naive split cut
/// `TE: deflate;ext="a,b"` — one member, one parameter — into a second "member"
/// of `b"`.
///
/// **That half is not universally right, and the test is the element's own
/// grammar.** Quote-awareness is correct exactly where the element admits a
/// `quoted-string` somewhere inside it. Where it does not — `acceptable-ranges =
/// 1#range-unit` and `range-unit = token`, or `Vary = #( "*" / field-name )` —
/// a DQUOTE is simply a character the member may not hold, and reading it as
/// opening a quoted-string makes the *next comma* data when the grammar has no
/// quoted-string for it to be data in. `Accept-Ranges: by"tes,none` is two
/// members to that field's production and one to this walk. So a `#token` list
/// keeps its naive split, and [`accept_ranges_values_valid`] says so at
/// its own walk.
///
/// [`accept_ranges_values_valid`]: crate::rules::accept_ranges_values_valid
///
/// The trim is `OWS` and not `str::trim`, for [`list_members`]'s reason: every
/// caller reads its field through [`combined_field_value_as_written`](crate::helpers::headers::combined_field_value_as_written), where
/// %xA0 and %x85 are `obs-text` octets a sender wrote *inside* a member.
///
/// **What each caller keeps is the wording of its own findings**, and they are
/// not the same findings: `Server-Timing` is `#`, so it has no floor at all and
/// only the empty-element half; `TE` reports the empty element after the members
/// that are present; `Warning` numbers it; `Prefer` and `Preference-Applied`
/// report the floor and the empty element as two separate sentences, because
/// § 5.6.1.2 makes a recipient accept what § 5.6.1.1 forbids a sender to write.
/// The walk is one thing; what it is walked *for* is twelve.
///
/// **Thirteen call sites in twelve rules, and the row that asked for this said
/// five.** The five were copies of the whole *preamble* — the walk plus a floor
/// finding plus a per-member empty finding — and what the same handover asked to
/// be extracted was the walk underneath it, which twelve rules perform, in six
/// spellings: collected-and-mapped, mapped-and-enumerated, mapped-and-`any`,
/// mapped-and-`filter_map`, trimmed inside the loop body, and one that trimmed
/// the `Vec` in place through `iter_mut`. **Count the thing being extracted, not
/// the symptom that made you notice it.**
///
// cite(RFC 9110 § 5.6.1.1): "1#element => element *( OWS "," OWS element )"
// cite(RFC 9110 § 5.6.3, label: OWS grammar): "OWS            = *( SP / HTAB )"
// cite(RFC 9110 § 5.6.4): "quoted-string  = DQUOTE *( qdtext / quoted-pair ) DQUOTE"
pub fn list_members_as_written(value: &str) -> Vec<&str> {
    // The `OWS` trim is the splitter's now, and this function is what it is for:
    // the splitter answers where the members are, and this name says that the
    // slices it hands back are the `1#element` expansion's elements.
    split_commas_respecting_quotes(value)
}

/// Split a comma-separated header value into top-level members while respecting quoted-strings
/// and backslash escapes. Returns a Vec of slices referencing the original string.
///
/// This is useful for header grammars like `Cache-Control` and `Pragma` where members
/// may contain quoted-strings with commas that must not be treated as separators.
///
/// **Each segment comes back without the `OWS` the `#rule` prints around its
/// commas**, which is what [`split_semicolons_respecting_quotes`] has always
/// done for the semicolon its own grammars print `OWS` around. The two were
/// asymmetric for no reason anyone had written down: every caller of this one
/// trimmed on the next line, and every one of them reached for `str::trim`.
///
/// That is why the asymmetry was worth removing rather than documenting.
/// `str::trim` is Unicode whitespace, and a value read through
/// [`combined_field_value_as_written`](crate::helpers::headers::combined_field_value_as_written) carries one `char` per octet — so %xA0
/// and %x85, the two `obs-text` octets that most look like a space, were removed
/// from a member's ends before any check could see them, and `obs-text` is
/// exactly the octet class no `token` admits. [`trim_ows`] is bounded to what
/// `OWS` is.
// cite(RFC 9110 § 5.6.1.1): "1#element => element *( OWS "," OWS element )"
// cite(RFC 9110 § 5.6.3, label: OWS grammar): "OWS            = *( SP / HTAB )"
pub fn split_commas_respecting_quotes(s: &str) -> Vec<&str> {
    split_top_level(s, b",")
}

/// Split `s` at every one of `separators` that is not inside a quoted-string,
/// returning the segments with the `OWS` their grammars print around the
/// separator removed.
///
/// **One walk, because there is one question.** This was written out twice —
/// once for the comma of a `#rule`, once for the semicolon of a parameter list —
/// and the copies were identical but for the byte compared, which is exactly the
/// shape that lets the two drift: a fix to the escape handling in one is a
/// silent non-fix in the other. `separators` is a byte string rather than one
/// byte because `Cache-Control` is read with a tolerance for both.
///
/// A backslash escapes only inside a quoted-string: `quoted-pair` is defined as
/// part of `quoted-string` and nowhere else, so outside one a backslash is an
/// ordinary octet. Both productions are transcribed at `validate_quoted_string`
/// below, which owns them; honouring an escape out here let a stray backslash
/// suppress the DQUOTE after it, flipping quote parity for the rest of the value
/// and swallowing every later member into one segment.
///
// cite(RFC 9110 § 5.6.4): "quoted-string  = DQUOTE *( qdtext / quoted-pair ) DQUOTE"
// cite(RFC 9110 § 5.6.3, label: OWS grammar): "OWS            = *( SP / HTAB )"
pub fn split_top_level<'a>(s: &'a str, separators: &[u8]) -> Vec<&'a str> {
    let mut res = Vec::new();
    let mut start = 0usize;
    let mut in_quote = false;
    let mut prev_backslash = false;

    for (i, b) in s.bytes().enumerate() {
        if prev_backslash {
            prev_backslash = false;
        } else if b == b'\\' && in_quote {
            prev_backslash = true;
        } else if b == b'"' {
            in_quote = !in_quote;
        } else if separators.contains(&b) && !in_quote {
            res.push(&s[start..i]);
            start = i + 1;
        }
    }
    res.push(&s[start..]);
    res.into_iter().map(trim_ows).collect()
}

/// Split a semicolon-separated header value into top-level members while respecting quoted-strings
/// and backslash escapes. Returns a Vec of slices referencing the original string.
///
/// Useful for header grammars like `Strict-Transport-Security` where directives are separated
/// with `;` and may include quoted-strings (rare but defensive).
/// Each segment comes back without the `OWS` the grammars print around their
/// semicolons, so no caller repeats the trim.
///
/// `str::trim` was wrong here for the same reason it is wrong on a member: a
/// value read through [`combined_field_value_as_written`](crate::helpers::headers::combined_field_value_as_written) carries one `char`
/// per octet, so %xA0 in it arrives as U+00A0 — `obs-text`, which no
/// parameter production admits and which `str::trim` removed, handing the
/// caller an *empty* segment and hiding the octet behind whichever finding
/// the caller has for emptiness. [`trim_ows`] is the same three characters of
/// intent bounded to what `OWS` is.
pub fn split_semicolons_respecting_quotes(s: &str) -> Vec<&str> {
    split_top_level(s, b";")
}

/// Whether every DQUOTE in `s` closes, under exactly the escape rules the two
/// splitters above use.
///
/// A quote-respecting splitter cannot return a trustworthy member list when the
/// quoting never closes: everything after the stray DQUOTE collapses into one
/// member, and no separator past it is a separator. A rule whose finding is
/// that some member is *absent* has to ask this first, or it states as missing
/// what is merely unreadable. Rules that judge a member they did find need no
/// such gate — that member was legible.
///
/// It lives beside the splitters because it has to agree with them about what a
/// quote is; a gate with its own idea of escaping would pass values the splitter
/// then mangles, or vice versa.
pub fn quoting_is_balanced(s: &str) -> bool {
    let mut in_quote = false;
    let mut prev_backslash = false;
    for b in s.bytes() {
        if prev_backslash {
            prev_backslash = false;
        // `quoted-pair` lives inside `quoted-string`, so a backslash outside
        // one escapes nothing.
        // cite(RFC 9110 § 5.6.4): "quoted-pair    = "\" ( HTAB / SP / VCHAR / obs-text )"
        } else if b == b'\\' && in_quote {
            prev_backslash = true;
        } else if b == b'"' {
            in_quote = !in_quote;
        }
    }
    !in_quote
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_members() {
        let input = " foo, bar , , baz ";
        let tokens: Vec<_> = list_members(input).collect();
        assert_eq!(tokens, vec!["foo", "bar", "baz"]);
    }

    /// Characterised rather than regressed: [`list_members`] already trimmed
    /// `OWS`, so this passes on the tree before `parse_list_header` was folded
    /// into it. What it pins is which *values* now reach here — every caller
    /// reads its field one `char` per octet, so %xA0 arrives as U+00A0 and %x85
    /// as U+0085. Both are `obs-text` a sender wrote *inside* the member, which
    /// is the octet class no `token` admits, so they have to survive the trim and
    /// reach the check that owns the member's grammar. The conversion's own
    /// regressions are the eight rule-level tests named in RULECITES §6's P17
    /// entry.
    #[test]
    fn list_members_trims_ows_and_not_the_obs_text_that_looks_like_space() {
        assert_eq!(
            list_members(" a ,\tb\t").collect::<Vec<_>>(),
            vec!["a", "b"]
        );

        let per_octet: String = [0xA0u8, b'a', 0xA0].iter().map(|&b| b as char).collect();
        let members: Vec<_> = list_members(&per_octet).collect();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].chars().count(), 3, "the obs-text octets survive");

        let lossy = String::from_utf8_lossy(b"gzip\xC2\xA0").into_owned();
        assert_eq!(list_members(&lossy).collect::<Vec<_>>(), vec!["gzip\u{A0}"]);

        // U+0085 is %x85 and tells the same story; `str::trim` removed both.
        let nel: String = [b'a', 0x85].iter().map(|&b| b as char).collect();
        assert_eq!(list_members(&nel).next().unwrap().chars().count(), 2);
    }

    /// The empty members are the point. The other list walk in this module drops
    /// them, which is right for a recipient and destroys the evidence for a rule
    /// measuring a sender: `1#`'s floor counts non-empty members, so a value of
    /// nothing but commas has to arrive as several empty members rather than as
    /// no members at all.
    #[test]
    fn list_members_as_written_keeps_what_the_recipients_walk_drops() {
        assert_eq!(list_members_as_written("a,,b"), vec!["a", "", "b"]);
        assert_eq!(list_members_as_written(""), vec![""]);
        assert_eq!(list_members_as_written(","), vec!["", ""]);
        assert_eq!(list_members_as_written(",   ,"), vec!["", "", ""]);
        // The same values through the recipient's walk, which is what the two
        // findings cannot be made from.
        assert_eq!(list_members("a,,b").collect::<Vec<_>>(), vec!["a", "b"]);
        assert!(list_members(",   ,").next().is_none());
    }

    /// A comma inside a `quoted-string` is `qdtext`, not a separator. The naive
    /// walk cut `TE: deflate;ext="a,b"` — one member — into a second "member" of
    /// `b"`.
    #[test]
    fn list_members_as_written_does_not_cut_inside_a_quoted_string() {
        assert_eq!(
            list_members_as_written(r#"deflate;ext="a,b", gzip"#),
            vec![r#"deflate;ext="a,b""#, "gzip"]
        );
        assert_eq!(list_members("a,b").collect::<Vec<_>>(), vec!["a", "b"]);
    }

    /// `OWS` is `*( SP / HTAB )` and nothing else. Every caller reads its field
    /// one `char` per octet, so %xA0 is an `obs-text` octet a sender wrote inside
    /// the member and trimming it would hand the member's own grammar a value
    /// nobody sent.
    #[test]
    fn list_members_as_written_trims_ows_and_not_unicode_whitespace() {
        assert_eq!(list_members_as_written(" a ,\tb\t"), vec!["a", "b"]);
        let padded: String = [0xA0u8, b'a', 0xA0].iter().map(|&b| b as char).collect();
        let members = list_members_as_written(&padded);
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].chars().count(), 3, "the obs-text octets survive");
    }

    /// The two splitters trim the same three characters of intent, and it is
    /// `OWS` rather than Unicode whitespace. Every caller of the comma splitter
    /// used to write `str::trim` on the next line, which is what this asserts is
    /// no longer needed and no longer right.
    #[test]
    fn both_splitters_trim_ows_and_only_ows() {
        assert_eq!(
            split_commas_respecting_quotes("  a , \tb\t ,c"),
            vec!["a", "b", "c"]
        );
        assert_eq!(
            split_semicolons_respecting_quotes("  a ; \tb\t ;c"),
            vec!["a", "b", "c"]
        );
        // %xA0 and %x85 arrive as U+00A0 and U+0085 from a value read one `char`
        // per octet. They are `obs-text`, which no `token` admits, so a member
        // that ends in one is a finding and not a member with trailing space —
        // and `str::trim` removed both.
        assert_eq!(
            split_commas_respecting_quotes("a\u{A0}, \u{85}b"),
            vec!["a\u{A0}", "\u{85}b"]
        );
        assert_eq!(
            split_semicolons_respecting_quotes("a\u{A0}; \u{85}b"),
            vec!["a\u{A0}", "\u{85}b"]
        );
        // An empty member stays an empty member: the trim removes whitespace,
        // never a member.
        assert_eq!(split_commas_respecting_quotes("a, ,b"), vec!["a", "", "b"]);
    }

    #[test]
    fn a_backslash_outside_a_quoted_string_escapes_nothing() {
        // `quoted-pair` is part of `quoted-string`, so outside one a backslash
        // is an ordinary octet. Honouring it there let a stray backslash eat
        // the DQUOTE after it, flipping quote parity and swallowing the rest of
        // the value into a single member.
        assert_eq!(
            split_commas_respecting_quotes(r#"text/html\, application/z+bogus"#),
            vec![r#"text/html\"#, "application/z+bogus"]
        );
        assert_eq!(
            split_semicolons_respecting_quotes(r#"text/html; p=a\; charset=utf-8"#),
            vec!["text/html", r#"p=a\"#, "charset=utf-8"]
        );
        // Inside a quoted-string it still escapes, including an escaped DQUOTE.
        assert_eq!(
            split_commas_respecting_quotes(r#"a;p="x\",y", b"#),
            vec![r#"a;p="x\",y""#, "b"]
        );
        assert_eq!(
            split_semicolons_respecting_quotes(r#"a; p="x\";y"; q=1"#),
            vec!["a", r#"p="x\";y""#, "q=1"]
        );
    }

    #[test]
    fn test_split_commas_respecting_quotes() {
        let cases = vec![
            ("a, b, c", vec!["a", "b", "c"]),
            ("token=\"a,b\", other", vec!["token=\"a,b\"", "other"]),
            (r#"token="a\"b",c"#, vec![r#"token="a\"b""#, "c"]),
            (
                "no-cache, foo=bar, token=\"quoted,comma\",baz",
                vec!["no-cache", "foo=bar", "token=\"quoted,comma\"", "baz"],
            ),
            ("", vec![""]),
            ("a,b,", vec!["a", "b", ""]),
            (",,", vec!["", "", ""]),
        ];

        for (input, expected) in cases {
            let got: Vec<String> = split_commas_respecting_quotes(input)
                .iter()
                .map(|s| s.trim().to_string())
                .collect();
            let exp: Vec<String> = expected.iter().map(|s| s.to_string()).collect();
            assert_eq!(got, exp, "input: {:?}", input);
        }
    }

    /// The gate has to agree with the splitters about what a quote is, so the
    /// pairs below are the cases where the two could disagree: a backslash
    /// outside a quoted-string escapes nothing, one inside escapes the next
    /// octet — including a DQUOTE that would otherwise close the string.
    #[test]
    fn test_quoting_is_balanced() {
        for s in [
            "",
            "a; b",
            "token=\"a;b\";x",
            "p=\"\"",
            "p=\"a\\\"b\"",
            // The backslash is outside a quoted-string, so it escapes nothing
            // and leaves no quote open.
            "p=a\\",
            "p=a\\; q=b",
        ] {
            assert!(quoting_is_balanced(s), "{s:?} should be balanced");
        }
        for s in [
            "p=\"x",
            "p=a\"b",
            "p=\"a\"\"",
            // The escaped DQUOTE does not close the string.
            "p=\"a\\\"",
        ] {
            assert!(!quoting_is_balanced(s), "{s:?} should be unbalanced");
        }
    }

    #[test]
    fn test_split_semicolons_respecting_quotes() {
        let cases = vec![
            ("a; b; c", vec!["a", "b", "c"]),
            (
                "max-age=63072000; includeSubDomains; preload",
                vec!["max-age=63072000", "includeSubDomains", "preload"],
            ),
            ("token=\"a;b\";x", vec!["token=\"a;b\"", "x"]),
            ("a;;b", vec!["a", "", "b"]),
            ("", vec![""]),
            ("a;", vec!["a", ""]),
        ];

        for (input, expected) in cases {
            let got: Vec<String> = split_semicolons_respecting_quotes(input)
                .iter()
                .map(|s| s.to_string())
                .collect();
            assert_eq!(got, expected);
        }
    }

    #[test]
    fn test_parse_semicolon_list_basic_cases() {
        let got: Vec<&str> = parse_semicolon_list("a; b; ; c; ").collect();
        assert_eq!(got, vec!["a", "b", "c"]);

        let got2: Vec<&str> = parse_semicolon_list("   ").collect();
        assert!(got2.is_empty());
    }

    #[test]
    fn test_parse_semicolon_list_unsafe_for_quoted_strings() {
        // Demonstrate that the naive parser does not respect quoted-strings.
        // This shows why callers that parse header parameters with quoted values
        // should prefer `split_semicolons_respecting_quotes`.
        let got: Vec<&str> = parse_semicolon_list("token=\"a;b\";x").collect();
        // naive split will break the quoted-string into multiple parts
        assert_eq!(got, vec!["token=\"a", "b\"", "x"]);
    }
}
