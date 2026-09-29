// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::helpers::cookie::find_invalid_cookie_octet;
use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::cookie::DRAFT_IETF_HTTPBIS_RFC6265BIS;
use crate::violations::cookie::{
    COOKIE_ATTRIBUTE_DUPLICATED, COOKIE_ATTRIBUTE_SEPARATOR_SPACE_MISSING, COOKIE_DOMAIN_MISSING,
    COOKIE_DOMAIN_MISSING_WORDING, COOKIE_EXPIRES_MALFORMED, COOKIE_EXPIRES_MISSING,
    COOKIE_FLAG_VALUE_FORBIDDEN, COOKIE_MAX_AGE_MALFORMED, COOKIE_MAX_AGE_MISSING,
    COOKIE_NAME_DUPLICATED, COOKIE_PAIR_EQUALS_MISSING, COOKIE_PAIR_MISSING, COOKIE_PATH_EMPTY,
    COOKIE_PATH_LEADING_SLASH_MISSING, COOKIE_PATH_MISSING, COOKIE_PATH_MISSING_WORDING,
    COOKIE_SAME_SITE_INVALID, COOKIE_SAME_SITE_MISSING, COOKIE_SECURE_MISSING,
    COOKIE_VALUE_CHARACTER_FORBIDDEN, RFC_6265_4_1_1, RFC_6265_5_1_1, RFC_6265_5_2, RFC_6265_5_2_2,
    RFC_6265_5_2_3, RFC_6265_5_2_4,
};
use crate::violations::domain::{DOMAIN_NAME_WHITESPACE_OR_CONTROL_FORBIDDEN, RFC_1035_2_3_1};
use crate::violations::http_date::{
    HTTP_DATE_DAY_NAME_CONFLICTING, HTTP_DATE_EMPTY, HTTP_DATE_MALFORMED, HTTP_DATE_OBSOLETE,
    RFC_5322_3_3, RFC_9110_5_6_7,
};
use crate::violations::token::{
    token_character, RFC_9110_5_6_2, TOKEN_CHARACTER_FORBIDDEN, TOKEN_EMPTY,
    TOKEN_WHITESPACE_OR_CONTROL_FORBIDDEN,
};
use crate::violations::ViolationDef;

pub struct CookieAttributeConsistent;

/// What this rule reports that another reading already named.
///
/// Five imports, each for a different reason. `sane-cookie-date` is RFC
/// 6265's name for the timestamp RFC 9110 § 5.6.7 writes, so the four ways an
/// `Expires` fails to be one a sender may generate are the four a `Date`, a
/// `Last-Modified` or a `Sunset` fails them in, drawn from the same subject.
/// What stays this field's own is the fifth answer — the value § 4.1.1 refuses
/// and § 5.1.1 reads anyway, which no other dated field has a recipient
/// algorithm for. `cookie-name = token` imports the HTTP production by name,
/// so a name that is empty or holds a delimiter answers to `token` — the
/// alphabets are not merely similar, they are the same set. `cookie-pair`'s
/// own two failures — no `=` at all, and a `cookie-value` octet outside
/// `cookie-octet` — are `cookie_pair_valid`'s ids too, reused rather than
/// redeclared for the same reason `cookie-name`'s are: the production is one
/// grammar shared by both directions the cookie travels, and an operator
/// tunes either shape once. And `Path` and `Domain` were read out by
/// `cookie_path_valid` and `cookie_domain_valid` first: this rule asks a
/// coarser question of the same two attributes, so it reports what they
/// report rather than a second name for it.
///
/// What is left in the rule's own words is the shape of the field line and the
/// attributes nothing else reads — `SameSite`, `Max-Age`, the two flags, and
/// the pairing that makes a `SameSite=None` cookie disappear — and § 4.1.1's
/// two repetitions: an attribute name a line writes twice, and a cookie-name a
/// response sets on two lines.
static DECLARED: &[&ViolationDef] = &[
    &HTTP_DATE_MALFORMED,
    &HTTP_DATE_EMPTY,
    &HTTP_DATE_OBSOLETE,
    &HTTP_DATE_DAY_NAME_CONFLICTING,
    &COOKIE_PAIR_MISSING,
    &COOKIE_PAIR_EQUALS_MISSING,
    &COOKIE_VALUE_CHARACTER_FORBIDDEN,
    &COOKIE_FLAG_VALUE_FORBIDDEN,
    &COOKIE_ATTRIBUTE_DUPLICATED,
    &COOKIE_ATTRIBUTE_SEPARATOR_SPACE_MISSING,
    &COOKIE_NAME_DUPLICATED,
    &COOKIE_SECURE_MISSING,
    &COOKIE_SAME_SITE_MISSING,
    &COOKIE_SAME_SITE_INVALID,
    &COOKIE_MAX_AGE_MISSING,
    &COOKIE_MAX_AGE_MALFORMED,
    &COOKIE_EXPIRES_MISSING,
    &COOKIE_EXPIRES_MALFORMED,
    &TOKEN_EMPTY,
    &TOKEN_CHARACTER_FORBIDDEN,
    &TOKEN_WHITESPACE_OR_CONTROL_FORBIDDEN,
    &COOKIE_PATH_MISSING,
    &COOKIE_PATH_EMPTY,
    &COOKIE_PATH_LEADING_SLASH_MISSING,
    &COOKIE_DOMAIN_MISSING,
    &DOMAIN_NAME_WHITESPACE_OR_CONTROL_FORBIDDEN,
];

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const MDN_SET_COOKIE: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "MDN Set-Cookie",
    section: None,
    url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie",
    note: "SameSite cookies (SameSite=None should be Secure) — browser compatibility guidance on `SameSite` usage",
};

impl CookieAttributeConsistent {
    /// What is wrong with one `Set-Cookie` field line.
    ///
    /// The line is a cookie-pair and then attributes, and those are two
    /// different grammars: the pair is judged here, each attribute by
    /// [`Self::attribute_defect`], and the one question that needs both — a
    /// `SameSite=None` cookie that is not `Secure` — after the walk.
    ///
    /// **The pair is one production and answers once; the attributes are a
    /// repetition and answer one apiece.** `cookie-av *( ";" SP cookie-av )`
    /// puts each attribute beside the others rather than inside them, so a
    /// cookie whose `Expires` names no instant and whose `Max-Age` holds no
    /// integer is two edits in two places, and a walk that stopped at the
    /// first of them named one of the two. Which is not what the pair's own
    /// reading is: there a name that is not a `token` and a value carrying a
    /// forbidden octet are two readings of one `cookie-pair`, taken left to
    /// right, and the second reads text the first has already condemned.
    ///
    /// **That paragraph was true of this function's documentation and false of
    /// its code.** The pair's reading `return`ed, so answering once meant
    /// answering for the whole *line*: a cookie whose pair did not derive had
    /// every attribute beside it judged by nothing. `Set-Cookie: a={"k":"1"};
    /// Expires=Sun, 30-Aug-2026 02:23:34 GMT` is one an origin sends — the
    /// DQUOTE and the comma are outside `cookie-octet`, and the hyphenated
    /// date behind them was never read. The pair's answer is now one finding
    /// among the line's rather than instead of them, which is what "two
    /// different grammars" was always supposed to mean.
    fn set_cookie_defects(
        &self,
        line: &str,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        let (pair, attributes) = crate::helpers::cookie::split_set_cookie(line);
        // Which cookie every sentence below is about. A response sets many,
        // and until each finding said which one it was for, two of them read
        // as one repeated. The name is empty exactly where the line wrote no
        // `=` to put one before, and `about_cookie` then leaves the sentence
        // alone rather than naming a cookie called nothing.
        let cookie = crate::helpers::cookie::set_cookie_name(line);
        let about = |sentence: &str| crate::helpers::cookie::about_cookie(cookie, sentence);

        // The pair answers once and the attributes answer one apiece, and this
        // is where that stops being only a sentence in the doc above. The pair
        // reading used to `return` from here, so its one finding was the whole
        // LINE's answer and every `cookie-av` after it went unread — a cookie
        // whose value carries a comma had its `Expires`, its `Max-Age` and its
        // `SameSite` judged by nothing, on real traffic.
        let mut out = Vec::new();
        out.extend(self.cookie_pair_defect(pair, cookie, ctx));

        let mut secure_present = false;
        let mut same_site: Option<String> = None;
        // Every attribute as written, under its folded name, so a name the
        // line gives twice is seen whatever case each occurrence is spelled in.
        let mut written: Vec<(String, Vec<String>)> = Vec::new();
        for attribute in attributes {
            out.extend(self.attribute_defect(&attribute, cookie, ctx));
            if !attribute.name.is_empty() {
                let folded = attribute.name.to_ascii_lowercase();
                let as_written = match attribute.value {
                    Some(value) => format!("{}={value}", attribute.name),
                    None => attribute.name.to_string(),
                };
                match written.iter_mut().find(|(name, _)| *name == folded) {
                    Some((_, occurrences)) => occurrences.push(as_written),
                    None => written.push((folded, vec![as_written])),
                }
            }
            // What the sender asked for, whether or not the asking was well
            // formed. A `SameSite` whose value no algorithm recognises is
            // still a `SameSite` the sender wrote, and the pairing below is
            // about which attributes are on the line rather than about
            // whether each derives — reading it off a walk that no longer
            // stops means an attribute past a defective one is seen at all.
            if attribute.is("secure") {
                secure_present = true;
            } else if attribute.is("samesite") {
                same_site = attribute.value.map(|v| v.to_ascii_lowercase());
            }
        }

        // `SameSite=None` without `Secure` is not a cookie with a weaker policy — it is
        // a cookie the user agent throws away. That is why this is a violation and not
        // a suggestion.
        // cite(draft-ietf-httpbis-rfc6265bis § 5.7): "If the cookie's "same-site-flag" is "None", abort this algorithm and ignore the cookie entirely unless the cookie's secure-only-flag is true."
        if same_site.as_deref() == Some("none") && !secure_present {
            out.push(ctx.report_with(
                &COOKIE_SECURE_MISSING,
                about("Set-Cookie with 'SameSite=None' must also set 'Secure'"),
            ));
        }

        out.extend(
            Self::separator_space_missing(line)
                .map(|m| ctx.report_with(&COOKIE_ATTRIBUTE_SEPARATOR_SPACE_MISSING, about(&m))),
        );

        // One finding per name written more than once, quoting each
        // occurrence: whether they agree is what the operator needs to know,
        // and a user agent reads only one of them.
        // cite(RFC 6265 § 4.1.1): "To maximize compatibility with user agents, servers SHOULD NOT produce two attributes with the same name in the same set-cookie-string."
        for (_, occurrences) in written.iter().filter(|(_, o)| o.len() > 1) {
            let quoted = occurrences
                .iter()
                .map(|o| format!("'{o}'"))
                .collect::<Vec<_>>()
                .join(", ");
            out.push(ctx.report_with(
                &COOKIE_ATTRIBUTE_DUPLICATED,
                about(&format!(
                    "Set-Cookie writes one attribute {} times: {quoted}",
                    occurrences.len()
                )),
            ));
        }
        out
    }

    /// The sentence for a line whose attributes follow their `;` without the
    /// `SP` § 4.1.1 prints there, naming each one, or `None`.
    ///
    /// Read off the segments as written, because the splitter every other
    /// question here asks trims them the way § 5.2 has a user agent do, and
    /// the space is exactly what that trim removes. An empty segment is
    /// skipped: a `;` at the end of the line or before another `;` is an empty
    /// `cookie-av`, which a space would not repair.
    // cite(RFC 6265 § 4.1.1): "set-cookie-string = cookie-pair *( ";" SP cookie-av )"
    fn separator_space_missing(line: &str) -> Option<String> {
        let mut total = 0;
        let mut unspaced = Vec::new();
        for segment in crate::helpers::cookie::set_cookie_segments_as_written(line) {
            if crate::helpers::headers::trim_ows(segment).is_empty() {
                continue;
            }
            total += 1;
            if !segment.starts_with(' ') {
                // Only the trailing whitespace goes, so a tab standing where
                // the space belongs is shown rather than trimmed away.
                let written = segment.trim_end_matches([' ', '\t']);
                unspaced.push(format!(
                    "'{}'",
                    crate::helpers::shown::shown_in_finding(written)
                ));
            }
        }
        (!unspaced.is_empty()).then(|| {
            format!(
                "Set-Cookie writes {} of its {total} attributes with no space after the ';' before it: {}; RFC 6265 § 4.1.1 separates each with '; '",
                unspaced.len(),
                unspaced.join(", ")
            )
        })
    }

    /// One finding per cookie-name the response sets on more than one line.
    ///
    /// The name is compared exactly, since § 5.3 stores `a` and `A` as two
    /// cookies, and a line with no name to compare is the pair reading's
    /// finding and not a cookie of this one's. Each line's value is quoted:
    /// under one scope the last replaces the others, and which one that was is
    /// what the operator reads next.
    // cite(RFC 6265 § 4.1.1): "Servers SHOULD NOT include more than one Set-Cookie header field in the same response with the same cookie-name."
    fn cookie_names_repeated(
        lines: &[String],
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        let mut by_name: Vec<(&str, Vec<&str>)> = Vec::new();
        for line in lines {
            let Some((name, value)) = crate::helpers::cookie::set_cookie_pair(line) else {
                continue;
            };
            if name.is_empty() {
                continue;
            }
            match by_name.iter_mut().find(|(n, _)| *n == name) {
                Some((_, values)) => values.push(value),
                None => by_name.push((name, vec![value])),
            }
        }
        by_name
            .into_iter()
            .filter(|(_, values)| values.len() > 1)
            .map(|(name, values)| {
                let quoted = values
                    .iter()
                    .map(|v| format!("'{v}'"))
                    .collect::<Vec<_>>()
                    .join(", ");
                ctx.report_with(
                    &COOKIE_NAME_DUPLICATED,
                    format!(
                        "The response sets cookie '{name}' on {} Set-Cookie lines, with the values {quoted}",
                        values.len()
                    ),
                )
            })
            .collect()
    }

    /// What is wrong with the `cookie-pair`, if anything.
    ///
    /// **One production, so one answer**, and that is the whole difference
    /// between this and [`Self::attribute_defect`]'s caller. A name that is not
    /// a `token` and a value carrying a forbidden octet are two readings of one
    /// `cookie-pair` taken left to right, and the second reads text the first
    /// has already condemned — so the first of them is the finding and the rest
    /// of the pair is not read again. The attributes beside it are a repetition
    /// and are none of this function's business.
    fn cookie_pair_defect(
        &self,
        pair: &str,
        cookie: &str,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Option<Violation> {
        let about = |sentence: &str| crate::helpers::cookie::about_cookie(cookie, sentence);
        if pair.is_empty() {
            return Some(ctx.report_with(
                &COOKIE_PAIR_MISSING,
                about("Set-Cookie header missing cookie-pair"),
            ));
        }

        // `cookie-pair = cookie-name "=" cookie-value` requires the `=`
        // unconditionally -- an empty value is legal (`SID=`) but no `=` at
        // all derives from neither alternative of the production. A bare
        // token here used to fall through this whole function silently: the
        // old reading took whatever preceded the first `=` as the name and
        // never asked whether an `=` had been there to precede.
        // cite(RFC 6265 § 4.1.1): "cookie-pair       = cookie-name "=" cookie-value cookie-name       = token"
        let Some((name, value)) = pair.split_once('=') else {
            return Some(ctx.report_with(
                &COOKIE_PAIR_EQUALS_MISSING,
                about(&format!("Set-Cookie pair '{pair}' has no '=': `cookie-pair = cookie-name \"=\" cookie-value` requires one")),
            ));
        };

        // The name is a `token` by import rather than by resemblance -- § 4.1.1
        // writes `cookie-name = token` and takes the production from the HTTP
        // document -- so both of its defects are that production's.
        let name = crate::helpers::headers::trim_ows(name);
        if name.is_empty() {
            return Some(ctx.report_with(&TOKEN_EMPTY, about("Set-Cookie cookie name is empty")));
        }
        if let Some(c) = crate::helpers::token::find_invalid_token_char(name) {
            return Some(ctx.report_with(
                token_character(c),
                about(&format!(
                    "Set-Cookie cookie-name contains invalid character: '{}'",
                    c
                )),
            ));
        }

        // `cookie-value = *cookie-octet / ( DQUOTE *cookie-octet DQUOTE )`,
        // the production's other half -- nothing before this read it either,
        // so a value carrying a comma, a bare quote or any other octet
        // outside `cookie-octet` passed as silently as a missing `=` did. A
        // semicolon in the value is already the caller's own `pair`, cut by
        // `split_set_cookie` before this point -- it reports above, on the
        // segment it starts, as a pair with no `=`.
        find_invalid_cookie_octet(value).map(|c| {
            ctx.report_with(
                &COOKIE_VALUE_CHARACTER_FORBIDDEN,
                about(&format!(
                    "Set-Cookie value '{value}' contains a character outside cookie-octet: '{c}'"
                )),
            )
        })
    }

    /// What is wrong with one `cookie-av`, if anything.
    ///
    /// An attribute this rule does not know is not a defect: the grammar ends
    /// in `extension-av`, and a user agent ignores what it does not recognise.
    // cite(RFC 6265 § 4.1.1): "extension-av      = <any CHAR except CTLs or ";">"
    fn attribute_defect(
        &self,
        attribute: &crate::helpers::cookie::Attribute<'_>,
        cookie: &str,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Option<Violation> {
        let about = |sentence: &str| crate::helpers::cookie::about_cookie(cookie, sentence);
        // The two flag attributes: the grammar admits no "=", so the attribute
        // is its own presence and a value written after it is a defect.
        // cite(RFC 6265 § 4.1.1): "secure-av         = "Secure""
        // cite(RFC 6265 § 4.1.1): "httponly-av       = "HttpOnly""
        for flag in ["Secure", "HttpOnly"] {
            if attribute.is(flag) {
                return attribute.has_value().then(|| {
                    ctx.report_with(
                        &COOKIE_FLAG_VALUE_FORBIDDEN,
                        about(&format!(
                            "Set-Cookie attribute '{}' must not have a value",
                            flag
                        )),
                    )
                });
            }
        }

        if attribute.is("SameSite") {
            let Some(value) = attribute.value else {
                return Some(ctx.report_with(
                    &COOKIE_SAME_SITE_MISSING,
                    about("Set-Cookie attribute 'SameSite' requires a value"),
                ));
            };
            let known = ["strict", "lax", "none"]
                .iter()
                .any(|known| value.eq_ignore_ascii_case(known));
            return (!known).then(|| {
                ctx.report_with(
                    &COOKIE_SAME_SITE_INVALID,
                    about(&format!(
                        "Set-Cookie attribute 'SameSite' has invalid value: '{}'",
                        value
                    )),
                )
            });
        }

        if attribute.is("Max-Age") {
            let Some(value) = attribute.value else {
                return Some(ctx.report_with(
                    &COOKIE_MAX_AGE_MISSING,
                    about("Set-Cookie attribute 'Max-Age' requires a numeric value"),
                ));
            };
            // A leading "-" is accepted on purpose: the ABNF says non-zero-digit
            // *DIGIT, but the parsing algorithm the ABNF is a summary of admits a
            // sign, and a negative Max-Age is how a cookie is deleted. The
            // reader is the store's, so the attribute reported as ignored is
            // the one the store ignores.
            // cite(RFC 6265 § 5.2.2): "If the first character of the attribute-value is not a DIGIT or a "-" character, ignore the cookie-av."
            if crate::helpers::cookie::max_age_seconds(value).is_some() {
                return None;
            }
            // The sentence names the octet a user agent stops at: `+60` is an
            // integer to most readers, and "not a valid integer" said nothing
            // they could act on.
            let digits = value.strip_prefix('-').unwrap_or(value);
            let why = match digits.chars().find(|c| !c.is_ascii_digit()) {
                Some(c) => format!("{c:?} is not a DIGIT"),
                None => "it holds no DIGIT".to_string(),
            };
            return Some(ctx.report_with(
                &COOKIE_MAX_AGE_MALFORMED,
                about(&format!(
                    "Set-Cookie attribute 'Max-Age' is '{value}': {why}, and a user agent ignores a Max-Age that is not DIGITs after an optional leading '-', so the cookie keeps no Max-Age lifetime"
                )),
            ));
        }

        if attribute.is("Expires") {
            let Some(value) = attribute.value else {
                return Some(ctx.report_with(
                    &COOKIE_EXPIRES_MISSING,
                    about("Set-Cookie attribute 'Expires' requires a HTTP-date value"),
                ));
            };
            // Two questions, and this used to ask the recipient's for both.
            // § 4.1.1 writes `sane-cookie-date` as `rfc1123-date`, which is the
            // one format § 5.6.7 lets a sender generate, so what the sender was
            // asked for is `check_imf_fixdate` and its answer is a defect rather
            // than a bool. `is_valid_http_date` stood here instead, and it is
            // the recipient's question by construction — it accepts all three
            // formats, because a recipient MUST — so the two spellings § 5.6.7
            // retired passed through it as conforming and this field said
            // nothing about them while every other dated field in the tree drew
            // `http_date_obsolete`.
            //
            // The recipient's question is still asked, and it is the second one:
            // § 5.2.1 sends a user agent to § 5.1.1 for this attribute, and that
            // algorithm reads hyphenated dates, two-digit years and an
            // unrecognised zone alike. Naming those `http_date_malformed` — an
            // id whose sentence is that the field names no instant — was untrue
            // while every user agent on the wire expired the cookie exactly when
            // the server meant, and `cookie_expires_malformed` is that narrower
            // half. It is reached from the one defect that leaves the value
            // deriving from no format at all; the other three derive from one,
            // so § 5.1.1 is not what is wrong with them.
            //
            // cite(RFC 6265 § 4.1.1): "expires-av        = "Expires=" sane-cookie-date"
            // cite(RFC 9110 § 5.6.7): "When a sender generates a field that contains one or more timestamps defined as HTTP-date, the sender MUST generate those timestamps in the IMF-fixdate format."
            let Err(defect) = crate::http_date::check_imf_fixdate(value) else {
                // One IMF-fixdate is not an `rfc1123-date`: the leap second.
                // § 5.6.7's `time-of-day` runs to `23:59:60` and RFC 2616's
                // `time`, the one § 4.1.1 names, stops a second short — and
                // § 5.1.1 aborts on it, so the attribute is ignored and the
                // cookie lasts for the session. Every other bound step 5 sets
                // is one the IMF-fixdate reader already holds.
                //
                // cite(RFC 6265 § 4.1.1): "sane-cookie-date  = <rfc1123-date, defined in [RFC2616], Section 3.3.1>"
                // cite(RFC 6265 § 5.1.1): "the second-value is greater than 59."
                if crate::helpers::cookie::cookie_date_is_readable(value) {
                    return None;
                }
                return Some(ctx.report_with(
                    &HTTP_DATE_MALFORMED,
                    about(&format!(
                        "Set-Cookie attribute 'Expires' is an HTTP-date with a leap second, \
                         which § 5.1.1 refuses, so a user agent ignores the attribute and \
                         keeps the cookie for the session: '{value}'"
                    )),
                ));
            };
            return Some(match defect {
                // An `Expires=` with nothing after the `=`. The bare attribute
                // is `cookie_expires_missing` two branches up — § 4.1.1 prints
                // the `=` between the name and the date, so writing neither and
                // writing only the first are different things a sender did.
                crate::http_date::HttpDateDefect::Empty => ctx.report_with(
                    &HTTP_DATE_EMPTY,
                    about("Set-Cookie attribute 'Expires' is written with no timestamp on it"),
                ),
                // RFC 850 or asctime. § 5.1.1 reads both and so does every user
                // agent, which is exactly what this entry says: the recipient is
                // obliged and the sender is refused. The same verdict
                // `expires_date_syntax` reaches on the sibling field, from the
                // same subject.
                crate::http_date::HttpDateDefect::ObsoleteFormat => ctx.report_with(
                    &HTTP_DATE_OBSOLETE,
                    about(&format!(
                        "Set-Cookie attribute 'Expires' is written in an obsolete date format; a \
                         recipient must read it, and a sender must generate IMF-fixdate: '{value}'"
                    )),
                ),
                // The one value here that *does* derive from `rfc1123-date`, so
                // `cookie_expires_malformed` would be false of it: what § 4.1.1
                // gets is the form it asked for, and what RFC 5322 § 3.3 refuses
                // is the weekday it names.
                crate::http_date::HttpDateDefect::DayNameConflicting => ctx.report_with(
                    &HTTP_DATE_DAY_NAME_CONFLICTING,
                    about(&format!(
                        "Set-Cookie attribute 'Expires' names a weekday its own date does not \
                         fall on: '{value}'"
                    )),
                ),
                // Padding cannot arrive: `split_set_cookie` trims the attribute
                // value before a rule sees it, so a `Expires= Sun, ...` reaches
                // here as the date alone. The sentence below would still be the
                // wrong one for it — the value derives from `IMF-fixdate` once
                // the octets § 4.1.1 never printed are taken off — and making it
                // answerable means the splitter handing the value over as
                // written, which is every attribute's question and not this
                // one's.
                crate::http_date::HttpDateDefect::SurroundingWhitespace
                | crate::http_date::HttpDateDefect::Unparsable => {
                    if crate::helpers::cookie::cookie_date_is_readable(value) {
                        ctx.report_with(
                            &COOKIE_EXPIRES_MALFORMED,
                            about(&format!(
                                "Set-Cookie attribute 'Expires' is not an rfc1123-date, though \
                                 § 5.1.1 reads it: '{value}'"
                            )),
                        )
                    } else {
                        ctx.report_with(
                            &HTTP_DATE_MALFORMED,
                            about(&format!(
                                "Set-Cookie attribute 'Expires' is not a valid HTTP-date: '{value}'"
                            )),
                        )
                    }
                }
            });
        }

        // `Path` and `Domain` are read here as far as their presence and their
        // first character, and in full by `cookie_path_valid` and
        // `cookie_domain_valid`. The coarser reading reports the same ids: what
        // an operator silences is the defect, not which of the two rules noticed
        // it first.
        if attribute.is("Path") {
            let Some(value) = attribute.value else {
                return Some(
                    ctx.report_with(&COOKIE_PATH_MISSING, about(COOKIE_PATH_MISSING_WORDING)),
                );
            };
            // `Some("")` is not a value of the wrong shape. § 5.2.4 tests
            // emptiness and the first character in one sentence, and the
            // catalogue splits them because the sender did: `cookie_path_empty`
            // is "`Path=` with nothing after the `=`", where `cookie_path_missing`
            // above is the bare attribute that never wrote an `=` at all. The
            // leading-slash entry is about a first character that is not `/`,
            // and an empty value has no first character — so this branch was
            // telling an operator to prefix a value that is not there.
            // cite(RFC 6265 § 5.2.4): "If the attribute-value is empty or if the first character of the attribute-value is not %x2F ("/"):"
            if value.is_empty() {
                return Some(ctx.report_with(
                    &COOKIE_PATH_EMPTY,
                    about("Set-Cookie attribute 'Path' is written with nothing after the '='"),
                ));
            }
            return (!value.starts_with('/')).then(|| {
                ctx.report_with(
                    &COOKIE_PATH_LEADING_SLASH_MISSING,
                    about(&format!(
                        "Set-Cookie attribute 'Path' should start with '/': '{}'",
                        value
                    )),
                )
            });
        }

        if attribute.is("Domain") {
            let Some(value) = attribute.value else {
                return Some(
                    ctx.report_with(&COOKIE_DOMAIN_MISSING, about(COOKIE_DOMAIN_MISSING_WORDING)),
                );
            };
            // The same reading as `Path` above, and the catalogue draws the
            // line in a different place for this attribute — deliberately.
            // `cookie_domain_missing` is defined as "`Domain` written with no
            // value, or with one that is empty before anything reads it", which
            // is this branch and the one above it; `cookie_domain_empty` is
            // reserved for a value that came to nothing *through the domain
            // reader* — `Domain=.`, empty once the tolerated leading dot comes
            // off — and its own definition says that is "why it is not
            // COOKIE_DOMAIN_MISSING". This rule reads the attribute and never
            // the domain, so it cannot be the one that reaches that entry, and
            // saying so here named a value the sender did not write.
            // cite(RFC 6265 § 5.2.3): "If the attribute-value is empty, the behavior is undefined."
            if value.is_empty() {
                return Some(
                    ctx.report_with(&COOKIE_DOMAIN_MISSING, about(COOKIE_DOMAIN_MISSING_WORDING)),
                );
            }
            // A space inside a host name is the *name's* defect and not the
            // attribute's: the same octet in a `Host`, a `Forwarded` host or a
            // `From` mailbox reports under this id already.
            return value.contains(' ').then(|| {
                ctx.report_with(
                    &DOMAIN_NAME_WHITESPACE_OR_CONTROL_FORBIDDEN,
                    about(&format!(
                        "Set-Cookie attribute 'Domain' must not contain spaces: '{}'",
                        value
                    )),
                )
            });
        }

        None
    }
}

impl RuleMeta for CookieAttributeConsistent {
    fn id(&self) -> &'static str {
        "cookie_attribute_consistent"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn description(&self) -> &'static str {
        "Validate `Set-Cookie` attributes for syntactic correctness and common security consistency rules. This rule parses `Set-Cookie` header values and flags:\n\n- Invalid cookie-name tokens.\n- Malformed attributes (e.g., `Max-Age` non-numeric, `Expires` not an HTTP-date).\n- `Path` values that don't start with `/`.\n- `Domain` values that are empty or contain spaces.\n- `SameSite` values other than `Strict`, `Lax`, or `None`.\n- `SameSite=None` cookies that are not marked `Secure` (browser behaviour / compatibility requirement).\n- `Secure` and `HttpOnly` attributes that incorrectly include a value (they must be flags).\n- One attribute name written twice on a line, compared case-insensitively (`Path=/; path=/`).\n- One cookie-name set on more than one `Set-Cookie` line of a response, compared exactly."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            RFC_6265_4_1_1,
            RFC_6265_5_1_1,
            RFC_6265_5_2,
            RFC_6265_5_2_2,
            RFC_6265_5_2_3,
            RFC_6265_5_2_4,
            DRAFT_IETF_HTTPBIS_RFC6265BIS,
            MDN_SET_COOKIE,
            RFC_9110_5_6_7,
            RFC_5322_3_3,
            RFC_9110_5_6_2,
            RFC_1035_2_3_1,
        ]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    fn party(&self) -> crate::rules::RuleParty {
        crate::rules::RuleParty::Presumed(crate::lint::Party::Server)
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet:
                    "Set-Cookie: SID=31d4d96e407aad42; Secure; HttpOnly; Path=/; SameSite=None",
            },
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "Set-Cookie: sid=abcd; Path=/login; HttpOnly",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some(
                    "— every user agent strips the whitespace, and § 4.1.1 still writes '; ' before each attribute",
                ),
                snippet: "Set-Cookie: SID=1;Path=/;Secure",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— SameSite=None must be Secure"),
                snippet: "Set-Cookie: id=1; SameSite=None",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— Max-Age must be numeric"),
                snippet: "Set-Cookie: SID=1; Max-Age=abc",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— a sign a user agent does not read, so the attribute is ignored"),
                snippet: "Set-Cookie: SID=1; Max-Age=+3600",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("— DIGITs of any width are a lifetime; a user agent caps it"),
                snippet: "Set-Cookie: SID=1; Max-Age=99999999999999999999",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— two cookies, two findings, each naming its own"),
                snippet: "Set-Cookie: a=1; Max-Age=soon\nSet-Cookie: b=2; SameSite=maybe",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some(
                    "— one cookie, two attributes, two findings: the attributes sit beside each other and neither is read out of the other",
                ),
                snippet: "Set-Cookie: a=1; Expires=NotADate; Max-Age=soon",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— Expires names no instant at all"),
                snippet: "Set-Cookie: SID=1; Expires=NotADate",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some(
                    "— the hyphenated form every user agent reads, which is still not the rfc1123-date § 4.1.1 asks a sender for",
                ),
                snippet: "Set-Cookie: SID=1; Expires=Wed, 27-Aug-2036 02:28:19 GMT",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some(
                    "— the same hyphenated form, on a day February does not have: no user agent reads it, so the expiry is dropped and the cookie lasts the session",
                ),
                snippet: "Set-Cookie: SID=1; Expires=Sat, 31-Feb-2026 00:00:00 GMT",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— a bare token has no '=', so it is no cookie-pair at all"),
                snippet: "Set-Cookie: SID",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— a comma is outside cookie-octet"),
                snippet: "Set-Cookie: SID=abc,def",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some(
                    "— one attribute in two spellings: attribute names fold, so this is Path written twice",
                ),
                snippet: "Set-Cookie: SID=1; Path=/; Max-Age=3600; path=/",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— one cookie set on two lines of one response"),
                snippet: "HTTP/1.1 200 OK\nSet-Cookie: SID=1; Path=/\nSet-Cookie: SID=2; Path=/",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("— a cookie-name does not fold: these are two cookies"),
                snippet: "HTTP/1.1 200 OK\nSet-Cookie: sid=1; Path=/\nSet-Cookie: SID=2; Path=/",
            },
        ]
    }
}

impl Rule for CookieAttributeConsistent {
    fn needs_response(&self) -> bool {
        true
    }

    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        let Some(resp) = tx.response.as_ref() else {
            return Vec::new();
        };
        // One finding per defective attribute, not one per response and not
        // one per cookie. `find_map` stood here first and stopped at the first
        // line with anything wrong with it, so a response setting a cookie
        // with a malformed `Max-Age` beside one with an unknown `SameSite`
        // reported the first and was silent about the second. Collecting the
        // lines left the same silence one level down, inside a line: the
        // attributes of one cookie are a repetition too.
        // Read as octets, one field line at a time: `Set-Cookie` is not a
        // list, and § 4.1.1's grammar stops at `CHAR`, so an octet above %x7F
        // is the attribute reader's finding rather than a verdict about the
        // field's encoding.
        let lines: Vec<String> = resp
            .headers
            .get_all("set-cookie")
            .iter()
            .map(crate::helpers::headers::field_line_as_written)
            .collect();
        let mut out: Vec<Violation> = lines
            .iter()
            .flat_map(|line| self.set_cookie_defects(line, ctx))
            .collect();
        out.extend(Self::cookie_names_repeated(&lines, ctx));
        out
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &CookieAttributeConsistent;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn check_set_cookie(value: &str) -> Option<Violation> {
        all_set_cookie(value).into_iter().next()
    }

    /// Every finding one `Set-Cookie` line draws, in the order the reader
    /// makes them. `run_rule` takes the first of however many, so a case
    /// asking a yes/no question cannot see a second finding arrive — which is
    /// the whole subject of this rule's walk.
    fn all_set_cookie(value: &str) -> Vec<Violation> {
        use crate::test_helpers::make_test_transaction_with_response;
        let tx = make_test_transaction_with_response(200, &[("set-cookie", value)]);
        let rule = CookieAttributeConsistent;
        crate::test_helpers::run_rule_all(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
    }

    /// A response is allowed to set many cookies, and this rule answers for
    /// each of them.
    ///
    /// `find_map` stood in the walk and stopped at the first line with
    /// anything wrong with it, so a malformed `Max-Age` on one cookie hid an
    /// unrecognised `SameSite` on the next — two different defects on two
    /// different cookies, one of them reported nowhere. Ten `Set-Cookie` lines
    /// is an ordinary response.
    /// § 4.1.1 prints one `SP` after each attribute's `;`. The finding is one
    /// per line and names every attribute written without it; an empty
    /// `cookie-av` and a second space are other shapes and draw nothing here.
    #[rstest]
    #[case(
        "a=b;Path=/;Secure",
        Some("Set-Cookie writes 2 of its 2 attributes with no space after the ';' before it: 'Path=/', 'Secure'; RFC 6265 § 4.1.1 separates each with '; ' (cookie 'a')")
    )]
    #[case(
        "a=b; Path=/;Secure",
        Some("Set-Cookie writes 1 of its 2 attributes with no space after the ';' before it: 'Secure'; RFC 6265 § 4.1.1 separates each with '; ' (cookie 'a')")
    )]
    #[case("a=b; Path=/; Secure", None)]
    #[case("a=b", None)]
    #[case("a=b; Path=/;", None)]
    #[case("a=b;; Path=/", None)]
    #[case("a=b;  Path=/", None)]
    fn an_attribute_separator_is_a_semicolon_and_one_space(
        #[case] value: &str,
        #[case] expected: Option<&str>,
    ) {
        let found: Vec<String> = all_set_cookie(value)
            .into_iter()
            .filter(|v| v.violation == "cookie_attribute_separator_space_missing")
            .map(|v| v.message)
            .collect();
        assert_eq!(found, Vec::from_iter(expected.map(str::to_string)));
    }

    /// A tab where the space belongs is not the space, and the sentence shows
    /// the tab rather than trimming it off the attribute it names.
    #[test]
    fn a_tab_after_the_semicolon_is_not_the_space_and_is_shown() {
        let found: Vec<Violation> = all_set_cookie("a=b;\tPath=/")
            .into_iter()
            .filter(|v| v.violation == "cookie_attribute_separator_space_missing")
            .collect();
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(
            !found[0].message.contains("'Path=/'"),
            "{:?}",
            found[0].message
        );
    }

    #[test]
    fn every_cookie_on_the_response_is_answered_for() {
        use crate::test_helpers::make_test_transaction_with_response;
        let tx = make_test_transaction_with_response(
            200,
            &[
                ("set-cookie", "a=1; Max-Age=soon"),
                ("set-cookie", "b=2; SameSite=maybe"),
            ],
        );
        let rule = CookieAttributeConsistent;
        let found = crate::test_helpers::run_rule_all(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        let ids: Vec<&str> = found.iter().map(|v| v.violation.as_str()).collect();
        assert_eq!(
            ids,
            ["cookie_max_age_malformed", "cookie_same_site_invalid"]
        );
        assert!(
            found[0].message.ends_with("(cookie 'a')"),
            "{:?}",
            found[0].message
        );
        assert!(
            found[1].message.ends_with("(cookie 'b')"),
            "{:?}",
            found[1].message
        );
    }

    /// The same entry twice on one response, which is what a repeated field
    /// makes ordinary: without the cookie's name the two findings are one
    /// sentence written twice, and an operator reading them cannot tell how
    /// many cookies they have to fix or which.
    #[test]
    fn two_findings_of_one_entry_are_told_apart_by_the_cookie() {
        use crate::test_helpers::make_test_transaction_with_response;
        let tx = make_test_transaction_with_response(
            200,
            &[
                ("set-cookie", "session=1; SameSite=None"),
                ("set-cookie", "tracker=2; SameSite=None"),
            ],
        );
        let rule = CookieAttributeConsistent;
        let found = crate::test_helpers::run_rule_all(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert_eq!(found.len(), 2);
        assert!(found.iter().all(|v| v.violation == "cookie_secure_missing"));
        assert_ne!(found[0].message, found[1].message);
        assert!(
            found[0].message.ends_with("(cookie 'session')"),
            "{:?}",
            found[0].message
        );
        assert!(
            found[1].message.ends_with("(cookie 'tracker')"),
            "{:?}",
            found[1].message
        );
    }

    /// Two defective attributes on one cookie are two edits, and each is
    /// named by the attribute it is about.
    ///
    /// `Expires` and `Max-Age` sit beside each other in `cookie-av *( ";" SP
    /// cookie-av )`; neither is inside the other and neither is read out of
    /// the other's text. A walk that answered once for the line told an
    /// operator to fix the date and said nothing about the integer.
    #[test]
    fn two_defective_attributes_of_one_cookie_are_two_findings() {
        let found = all_set_cookie("a=b; Expires=notadate; Max-Age=xyz");
        assert_eq!(found.len(), 2, "{found:?}");
        assert_eq!(found[0].violation, "http_date_malformed");
        assert!(
            found[0].message.contains("'Expires'"),
            "{:?}",
            found[0].message
        );
        assert_eq!(found[1].violation, "cookie_max_age_malformed");
        assert!(
            found[1].message.contains("'Max-Age'"),
            "{:?}",
            found[1].message
        );
        assert!(
            found.iter().all(|v| v.message.ends_with("(cookie 'a')")),
            "{found:?}"
        );
    }

    /// Three of them, so the count is a count and not the pair the fix was
    /// written against.
    #[test]
    fn three_defective_attributes_of_one_cookie_are_three_findings() {
        let found = all_set_cookie("a=b; SameSite=Bogus; Max-Age=xyz; Secure=1");
        assert_eq!(
            found
                .iter()
                .map(|v| v.violation.as_str())
                .collect::<Vec<_>>(),
            vec![
                "cookie_same_site_invalid",
                "cookie_max_age_malformed",
                "cookie_flag_value_forbidden",
            ],
            "{found:?}"
        );
    }

    /// The other direction: a conforming cookie stays silent however many
    /// attributes it carries, so the walk collecting is not the walk reporting.
    #[test]
    fn a_conforming_cookie_with_many_attributes_is_silent() {
        assert!(all_set_cookie(
            "a=b; Expires=Wed, 09 Jun 2021 10:18:14 GMT; Max-Age=60; \
                 Path=/; Domain=example.com; Secure; HttpOnly; SameSite=Lax"
        )
        .is_empty());
    }

    /// An attribute past a defective one is still read for the pairing that
    /// needs two of them. Before the walk collected, the `Secure` on this line
    /// was never reached — the `SameSite` returned first — and `secure_present`
    /// stayed false, so a cookie that *is* `Secure` was about to be told it was
    /// not. The finding the flag's own value draws stands; the pairing does not.
    #[test]
    fn an_attribute_after_a_defective_one_still_counts_for_the_pairing() {
        let found = all_set_cookie("a=b; SameSite=None; Secure=1");
        assert_eq!(
            found
                .iter()
                .map(|v| v.violation.as_str())
                .collect::<Vec<_>>(),
            vec!["cookie_flag_value_forbidden"],
            "{found:?}"
        );
    }

    /// A defective `cookie-pair` still answers once: its name and its value
    /// are two readings of one production taken left to right, and the second
    /// reads octets the first has already condemned. `a@b` is outside `token`
    /// and `c,d` is outside `cookie-octet`, and only the first is reported.
    ///
    /// **The `Max-Age` is here on purpose, and it used not to be reported.**
    /// This test asserted the line's whole answer was the pair's one finding,
    /// which is the masking rather than the once-ness: answering once is a
    /// claim about the *pair*, and the attributes beside it are a separate
    /// production that answers for itself.
    #[test]
    fn a_defective_pair_answers_once() {
        let found = all_set_cookie("a@b=c,d; Max-Age=xyz");
        assert_eq!(
            found
                .iter()
                .map(|v| v.violation.as_str())
                .collect::<Vec<_>>(),
            vec!["token_character_forbidden", "cookie_max_age_malformed"],
            "{found:?}"
        );
    }

    /// Each of the five ways a `cookie-pair` can fail to derive, and the
    /// attributes behind it in every one of them.
    ///
    /// The pair's finding used to be the whole line's answer, so the three
    /// attribute entries below were unreachable through any of these five
    /// values — on real traffic, through the last of them: a cookie whose
    /// value is a JSON document carries DQUOTE and comma, and the hyphenated
    /// `Expires` behind it was read by nothing.
    ///
    /// The sixth row is the control. Without it, five green rows would be
    /// consistent with the attributes being unreportable for some other
    /// reason.
    #[rstest]
    #[case("", "cookie_pair_missing")]
    #[case("justaname", "cookie_pair_equals_missing")]
    #[case("=v", "token_empty")]
    #[case("a b=v", "token_whitespace_or_control_forbidden")]
    #[case(r#"a={"k":"1","j":"2"}"#, "cookie_value_character_forbidden")]
    fn a_pair_that_does_not_derive_leaves_its_attributes_readable(
        #[case] pair: &str,
        #[case] pair_defect: &str,
    ) {
        let found = all_set_cookie(&format!(
            "{pair}; Expires=Sun, 30-Aug-2026 02:23:34 GMT; Max-Age=soon; SameSite=None"
        ));
        let ids = found
            .iter()
            .map(|v| v.violation.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            ids,
            vec![
                pair_defect,
                "cookie_expires_malformed",
                "cookie_max_age_malformed",
                "cookie_secure_missing",
            ],
            "{found:?}"
        );
    }

    /// The control for the five above: the same attributes behind a pair that
    /// derives, which is where the three entries were always reachable.
    #[test]
    fn a_pair_that_derives_contributes_nothing_of_its_own() {
        let found = all_set_cookie(
            "a=v; Expires=Sun, 30-Aug-2026 02:23:34 GMT; Max-Age=soon; SameSite=None",
        );
        assert_eq!(
            found
                .iter()
                .map(|v| v.violation.as_str())
                .collect::<Vec<_>>(),
            vec![
                "cookie_expires_malformed",
                "cookie_max_age_malformed",
                "cookie_secure_missing",
            ],
            "{found:?}"
        );
    }

    /// A line with no `=` has no cookie-name to be named by, and the sentence
    /// is left as it is rather than naming a cookie called nothing.
    #[test]
    fn a_line_with_no_name_is_not_named() {
        let v = check_set_cookie("SID").expect("a finding");
        assert_eq!(v.violation, "cookie_pair_equals_missing");
        assert!(!v.message.contains("(cookie"), "{:?}", v.message);
    }

    #[rstest]
    #[case("SID=31d4d96e407aad42; Secure; HttpOnly; Path=/; SameSite=None", false)]
    #[case("sid=abcd; Path=/login; HttpOnly", false)]
    #[case("id=1; SameSite=Strict; Secure", false)]
    #[case("id=1; SameSite=None", true)]
    #[case("id=1; SameSite=none", true)]
    #[case("id=1; SameSite=Weird", true)]
    #[case("=bad; Secure", true)]
    #[case("SID=1; Max-Age=abc", true)]
    #[case("SID=1; Max-Age=10", false)]
    // § 5.2.2's first gate refuses the sign `str::parse` accepts, and no gate
    // asks how wide the DIGITs run.
    #[case("SID=1; Max-Age=+60", true)]
    #[case("SID=1; Max-Age=-", true)]
    #[case("SID=1; Max-Age=99999999999999999999", false)]
    #[case("SID=1; Max-Age=0060", false)]
    #[case("SID=1; Expires=NotADate", true)]
    #[case("SID=1; Expires=Wed, 21 Oct 2015 07:28:00 GMT", false)]
    #[case("SID=1; Path=login", true)]
    #[case("SID=1; Path", true)]
    #[case("SID=1; Domain=bad host", true)]
    #[case("SID=1; Domain", true)]
    #[case("SID=1; Secure=1", true)]
    #[case("SID=1; HttpOnly=1", true)]
    #[case("SID=1; SameSite", true)]
    // A bare token with no `=` at all: `cookie-pair` has no alternative
    // without one, so this is not a name with an empty value -- it is no
    // cookie-pair, and the cookie is lost the same way an empty pair loses
    // it. Was silently accepted; see `cookie_pair_equals_missing` below.
    #[case("SID", true)]
    #[case("", true)]
    // `cookie-value`'s own grammar, read for the first time: a comma and a
    // raw space are both outside `cookie-octet`.
    #[case("SID=abc,def", true)]
    #[case("SID=has space", true)]
    // The DQUOTE-wrapped alternative `cookie-value` offers, legal.
    #[case("SID=\"has space\"", true)]
    #[case("SID=\"abcdef\"", false)]
    fn set_cookie_cases(#[case] value: &str, #[case] expect_violation: bool) {
        let v = check_set_cookie(value);
        if expect_violation {
            assert!(v.is_some(), "expected violation for '{}', got none", value);
        } else {
            assert!(v.is_none(), "unexpected violation for '{}': {:?}", value, v);
        }
    }

    /// Which of the two `Expires` ids a value draws, and the rule is whether a
    /// user agent can read it. Every value here but the last two was taken off
    /// the wire from a widely used origin, and each one used to be reported as
    /// naming no instant.
    #[rstest]
    // rfc1123-date, so no finding at all.
    #[case("SID=1; Expires=Wed, 21 Oct 2015 07:28:00 GMT", None)]
    // `obs-date`, RFC 850's spelling. It parses, every user agent reads it and
    // § 5.6.7 refuses a sender both of the formats that do — the answer
    // `expires_date_syntax` reaches on the sibling field, from the same subject.
    // This row asserted `None` for as long as the reading was a recipient's.
    #[case(
        "SID=1; Expires=Monday, 30-Aug-27 01:13:44 GMT",
        Some("http_date_obsolete")
    )]
    // `obs-date`'s other half: asctime, whose zone is implicit and whose day of
    // the month is space-padded.
    #[case("SID=1; Expires=Sun Nov  6 08:49:37 1994", Some("http_date_obsolete"))]
    // The one value here that *is* an rfc1123-date: § 4.1.1 got the form it asked
    // for, and the sixth of November 1994 was a Sunday. `cookie_expires_malformed`
    // would say the form is wrong, which is the false half.
    #[case(
        "SID=1; Expires=Mon, 06 Nov 1994 08:49:37 GMT",
        Some("http_date_day_name_conflicting")
    )]
    // An `=` with nothing after it. The bare attribute is `cookie_expires_missing`
    // below; this one wrote the delimiter and then no timestamp.
    #[case("SID=1; Expires=", Some("http_date_empty"))]
    // `-` is a § 5.1.1 delimiter, so this is `30 Aug 2026` to every user agent.
    #[case(
        "SID=1; Expires=Sun, 30-Aug-2026 02:23:34 GMT",
        Some("cookie_expires_malformed")
    )]
    // `year = 2*4DIGIT`, and 0-69 maps onto 20xx: this is 2027.
    #[case(
        "SID=1; Expires=Mon, 30-Aug-27 01:13:44 GMT",
        Some("cookie_expires_malformed")
    )]
    // No production matches the zone, so `UTC` is skipped and step 6 says UTC.
    #[case(
        "SID=1; Expires=Mon, 31 Aug 2026 00:16:39 UTC",
        Some("cookie_expires_malformed")
    )]
    // No time, no month, no year: § 5.1.1 fails too, so it names no instant.
    #[case("SID=1; Expires=NotADate", Some("http_date_malformed"))]
    // § 5.1.1 tokenizes this fine and then step 5 rejects the day-of-month.
    #[case(
        "SID=1; Expires=Sun, 32 Aug 2026 00:31:33 GMT",
        Some("http_date_malformed")
    )]
    // And the year floor, which is § 5.1.1's own and not the grammar's.
    #[case(
        "SID=1; Expires=Sun, 30-Aug-1500 02:23:34 GMT",
        Some("http_date_malformed")
    )]
    // Step 6's abort, which no bound in step 5 can state: every field is in
    // range and the six of them name no day. A user agent fails to parse these
    // and ignores the attribute, so the cookie it was given an expiry for
    // becomes a session cookie — which is `http_date_malformed`'s subject and
    // not this entry's.
    #[case(
        "SID=1; Expires=Sat, 31-Feb-2026 00:00:00 GMT",
        Some("http_date_malformed")
    )]
    #[case(
        "SID=1; Expires=Fri, 31-Apr-2026 00:00:00 GMT",
        Some("http_date_malformed")
    )]
    // A common year has no 29 February; the leap year below does, and the same
    // reading has to keep it readable.
    #[case(
        "SID=1; Expires=Sun, 29-Feb-2027 00:00:00 GMT",
        Some("http_date_malformed")
    )]
    #[case(
        "SID=1; Expires=Thu, 29-Feb-2024 00:00:00 GMT",
        Some("cookie_expires_malformed")
    )]
    // A year before the Unix epoch is an `rfc1123-date` and § 5.1.1 reads it:
    // the year floor there is 1601.
    #[case("SID=1; Expires=Wed, 31 Dec 1969 23:59:59 GMT", None)]
    #[case("SID=1; Expires=Mon, 01 Jan 1900 00:00:00 GMT", None)]
    // The leap second is an HTTP-date and not an `rfc1123-date`, and step 5
    // refuses it, so the cookie lasts for the session.
    #[case(
        "SID=1; Expires=Sat, 31 Dec 2016 23:59:60 GMT",
        Some("http_date_malformed")
    )]
    fn expires_reports_what_a_user_agent_can_read(
        #[case] value: &str,
        #[case] expected: Option<&str>,
    ) {
        let found = check_set_cookie(value);
        match expected {
            None => assert!(
                found.is_none(),
                "unexpected violation for '{value}': {found:?}"
            ),
            Some(id) => {
                let found =
                    found.unwrap_or_else(|| panic!("expected {id} for '{value}', got none"));
                assert_eq!(found.violation, id, "wrong id for '{value}'");
            }
        }
    }

    /// The five attributes that take a value, each written as a bare name with
    /// no `=` behind it — the shape § 5.2 gives an empty attribute-value, and
    /// the sender gets none of what they asked for.
    ///
    /// One row per attribute because they are five independent branches and
    /// were not equally written: `Path`, `Domain` and `SameSite` had a case
    /// apiece asserting only that *something* was reported, and `Expires` and
    /// `Max-Age` had none at all — their only coverage of an absent value was a
    /// malformed *value*, which reaches a different branch entirely. Asserting
    /// the id rather than a boolean is what makes each row say which branch
    /// ran: every value here has a defective cookie-pair reading and a grammar
    /// reading standing ready to answer instead.
    #[rstest]
    #[case("SID=1; Expires", "cookie_expires_missing")]
    #[case("SID=1; Max-Age", "cookie_max_age_missing")]
    #[case("SID=1; SameSite", "cookie_same_site_missing")]
    #[case("SID=1; Path", "cookie_path_missing")]
    #[case("SID=1; Domain", "cookie_domain_missing")]
    fn an_attribute_written_with_no_value_says_which_one(
        #[case] value: &str,
        #[case] expected: &str,
    ) {
        let found = check_set_cookie(value)
            .unwrap_or_else(|| panic!("expected {expected} for '{value}', got none"));
        assert_eq!(found.violation, expected, "wrong id for '{value}'");
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let rule = CookieAttributeConsistent;
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        cfg.rules.insert(
            "cookie_attribute_consistent".into(),
            toml::Value::Table(table),
        );

        // validate should succeed without error
        rule.prepare(&cfg)?;
        Ok(())
    }

    #[test]
    fn an_obs_text_octet_is_read_where_it_lands() -> anyhow::Result<()> {
        use crate::http_transaction::ResponseInfo;
        use crate::test_helpers::make_test_transaction;
        use hyper::header::HeaderValue;

        let mut tx = make_test_transaction();
        tx.response = Some(ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hyper::HeaderMap::new(),

            body_length: None,
            body_interrupted: false,
            trailers: None,
        });

        // A field line holding an octet above %x7F, in the cookie-name half
        // of an otherwise well-formed pair -- the `=` is what keeps this test
        // about the name's own character class rather than about the missing
        // `=` `cookie_pair_equals_missing` now reports first for a bare
        // octet with none.
        tx.response
            .as_mut()
            .unwrap()
            .headers
            .append("set-cookie", HeaderValue::from_bytes(&[0xff, b'=', b'1'])?);

        let rule = CookieAttributeConsistent;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        // The octet is in the cookie-name, and that is what the finding says
        // now: § 4.1.1 writes the name as a `token`, so an octet above %x7F is
        // a character it does not admit. The verdict this replaces named the
        // field's encoding and stopped before the name was read.
        //
        // The name is also what the finding is about, so it is named twice —
        // once as the character that is wrong and once as the cookie the wrong
        // character belongs to. That reads oddly for a one-octet name and is
        // exactly right beside a second cookie on the same response, which is
        // the case the suffix exists for.
        let v = v.expect("a finding");
        assert_eq!(
            v.message,
            "Set-Cookie cookie-name contains invalid character: '\u{ff}' (cookie '\u{ff}')"
        );
        Ok(())
    }

    #[test]
    fn invalid_cookie_name_token_reports_char() {
        // Name containing invalid token character '@' should be reported
        let v = check_set_cookie("N@ME=1; Secure");
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("invalid character") && msg.contains("@"));
    }

    /// `cookie_pair_valid` declares this id on the request side; this is the
    /// same id reported here, on `Set-Cookie`, for the same production.
    #[test]
    fn a_bare_token_with_no_equals_is_no_cookie_pair() {
        let v = check_set_cookie("SID").expect("a finding");
        assert_eq!(v.violation, "cookie_pair_equals_missing");
    }

    /// The other half of `cookie-pair` that had never been read: `Set-Cookie`
    /// validated `cookie-name` and skipped `cookie-value` entirely.
    #[test]
    fn a_cookie_value_octet_outside_cookie_octet_is_reported() {
        let v = check_set_cookie("SID=abc,def").expect("a finding");
        assert_eq!(v.violation, "cookie_value_character_forbidden");
        assert!(v.message.contains("','"), "{}", v.message);
    }

    /// The DQUOTE-wrapped alternative `cookie-value` offers is read the same
    /// way on both sides of the cookie: legal when its content is, illegal
    /// when a forbidden octet -- here, the space -- is inside the quotes too.
    #[test]
    fn a_quoted_cookie_value_is_read_inside_its_quotes() {
        assert!(check_set_cookie("SID=\"abcdef\"").is_none());
        let v = check_set_cookie("SID=\"has space\"").expect("a finding");
        assert_eq!(v.violation, "cookie_value_character_forbidden");
    }

    #[test]
    fn unknown_attribute_is_ignored() {
        // Unknown attribute 'Foo=bar' should not cause a violation
        let v = check_set_cookie("id=1; Foo=bar");
        assert!(v.is_none());
    }

    #[test]
    fn trailing_empty_attribute_ignored_and_path_ok() {
        // Trailing empty attribute should be skipped; Path value trimmed and checked
        let v = check_set_cookie("SID=1; ; Path= /home ");
        assert!(v.is_none());
    }

    #[test]
    fn secure_with_empty_value_is_accepted_but_secure_with_value_reports() {
        // Secure= (empty) is accepted by current implementation
        let v_ok = check_set_cookie("SID=1; Secure=");
        assert!(v_ok.is_none());

        // Secure=1 with a value is a violation (already covered in parametrized cases)
        let v_bad = check_set_cookie("SID=1; Secure=1");
        assert!(v_bad.is_some());
    }

    #[test]
    fn cookie_value_with_equals_is_valid() {
        // Cookie value containing '=' characters should be accepted
        let v = check_set_cookie("SID=abc=def; Path=/");
        assert!(v.is_none());
    }

    #[test]
    fn multiple_set_cookie_headers_one_invalid_reports_violation() -> anyhow::Result<()> {
        use crate::http_transaction::ResponseInfo;
        use crate::test_helpers::make_test_transaction;
        use hyper::header::HeaderValue;

        let mut tx = make_test_transaction();
        tx.response = Some(ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hyper::HeaderMap::new(),

            body_length: None,
            body_interrupted: false,
            trailers: None,
        });

        // Append a valid and an invalid Set-Cookie header
        tx.response
            .as_mut()
            .unwrap()
            .headers
            .append("set-cookie", HeaderValue::from_static("SID=1; Path=/"));
        tx.response
            .as_mut()
            .unwrap()
            .headers
            .append("set-cookie", HeaderValue::from_static("=bad; Secure"));

        let rule = CookieAttributeConsistent;
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn samesite_requires_value_reports_message() {
        let v = check_set_cookie("SID=1; SameSite");
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("requires a value"));
    }

    #[test]
    fn lone_semicolon_is_missing_cookie_pair() {
        let v = check_set_cookie("; Secure");
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("missing cookie-pair"));
    }

    /// An attribute written with an empty value is not an attribute whose
    /// value has the wrong shape, and the catalogue splits the two per
    /// attribute rather than in general — so each half is pinned by the id it
    /// draws and not by a word in its sentence.
    ///
    /// `Domain=` is `cookie_domain_missing`, whose definition covers a value
    /// "empty before anything reads it"; `cookie_domain_empty` belongs to
    /// `Domain=.`, which only the domain reader can see and which this rule
    /// does not run. `Path=` is `cookie_path_empty`, which the catalogue keeps
    /// apart from the bare `Path` above it because the operator's fix differs;
    /// the leading-slash entry is about a first character, and an empty value
    /// has none.
    #[rstest]
    #[case("SID=1; Domain=", "cookie_domain_missing")]
    #[case("SID=1; Domain", "cookie_domain_missing")]
    #[case("SID=1; Path=", "cookie_path_empty")]
    #[case("SID=1; Path", "cookie_path_missing")]
    #[case("SID=1; Path=x", "cookie_path_leading_slash_missing")]
    fn an_empty_attribute_value_draws_the_entry_written_for_it(
        #[case] value: &str,
        #[case] expected: &str,
    ) {
        let v = check_set_cookie(value).expect("a finding");
        assert_eq!(v.violation, expected, "{value}: {}", v.message);
    }

    /// The two entries this rule may not reach, stated as the negative so a
    /// return to either shape fails here rather than in a report. `Domain=.`
    /// is `cookie_domain_empty`'s value and is reached through the domain
    /// reader, which is a different rule; the leading-slash claim is about a
    /// character that an empty value does not have.
    #[test]
    fn an_empty_value_is_never_named_as_a_value_of_the_wrong_shape() {
        for line in ["SID=1; Domain=", "SID=1; Domain=."] {
            for v in all_set_cookie(line) {
                assert_ne!(v.violation, "cookie_domain_empty", "{line}: {}", v.message);
            }
        }
        for v in all_set_cookie("SID=1; Path=") {
            assert_ne!(
                v.violation, "cookie_path_leading_slash_missing",
                "an empty Path has no first character: {}",
                v.message
            );
        }
    }

    /// Every finding a response's `Set-Cookie` lines draw, as ids.
    fn ids_for_lines(lines: &[&str]) -> Vec<String> {
        use crate::test_helpers::make_test_transaction_with_response;
        let headers: Vec<(&str, &str)> = lines.iter().map(|l| ("set-cookie", *l)).collect();
        let tx = make_test_transaction_with_response(200, &headers);
        let rule = CookieAttributeConsistent;
        crate::test_helpers::run_rule_all(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
        .into_iter()
        .map(|v| v.violation)
        .collect()
    }

    /// A name the line gives twice, whatever case each occurrence is spelled
    /// in and whether or not the name is one § 4.1.1 defines; and the lines
    /// that give each name once.
    #[rstest]
    #[case::two_spellings("a=b; Path=/; Max-Age=60; path=/", 1)]
    #[case::values_differ("a=b; Max-Age=0; Max-Age=3600", 1)]
    #[case::a_flag("a=b; HttpOnly; httponly", 1)]
    #[case::an_extension("a=b; Priority=High; Priority=Low", 1)]
    #[case::three_times_is_one_finding("a=b; Path=/; Path=/; PATH=/", 1)]
    #[case::two_names_twice("a=b; Path=/; Secure; path=/x; secure", 2)]
    #[case::each_once("a=b; Path=/; Max-Age=60; Secure; HttpOnly; SameSite=Lax", 0)]
    #[case::expires_and_max_age("a=b; Expires=Sun, 06 Nov 2044 08:49:37 GMT; Max-Age=60", 0)]
    #[case::stray_semicolons("a=b; ; Path=/;", 0)]
    fn an_attribute_name_written_twice(#[case] line: &str, #[case] findings: usize) {
        let ids = ids_for_lines(&[line]);
        let drawn = ids
            .iter()
            .filter(|id| *id == "cookie_attribute_duplicated")
            .count();
        assert_eq!(drawn, findings, "{line}: {ids:?}");
    }

    #[test]
    fn a_repeated_attribute_is_quoted_as_written() {
        let found = all_set_cookie("lmd=1; Path=/; max-age=60; path=/");
        let v = found
            .iter()
            .find(|v| v.violation == "cookie_attribute_duplicated")
            .expect("Path written twice");
        assert_eq!(
            v.message,
            "Set-Cookie writes one attribute 2 times: 'Path=/', 'path=/' (cookie 'lmd')"
        );
    }

    /// A cookie-name set on two lines, under one scope or two; and names that
    /// differ, including only in case, which are two cookies.
    #[rstest]
    #[case::same_scope(&["a=1; Path=/", "a=2; Path=/"], 1)]
    #[case::two_paths(&["a=1; Path=/", "a=2; Path=/x"], 1)]
    #[case::three_lines_one_finding(&["a=1", "a=2", "a=3"], 1)]
    #[case::two_names_each_twice(&["a=1", "b=1", "a=2", "b=2"], 2)]
    #[case::two_names(&["a=1; Path=/", "b=2; Path=/"], 0)]
    #[case::names_differ_in_case(&["a=1; Path=/", "A=2; Path=/"], 0)]
    #[case::no_name_to_compare(&["=1", "=2"], 0)]
    fn a_cookie_name_on_more_than_one_line(#[case] lines: &[&str], #[case] findings: usize) {
        let ids = ids_for_lines(lines);
        let drawn = ids
            .iter()
            .filter(|id| *id == "cookie_name_duplicated")
            .count();
        assert_eq!(drawn, findings, "{lines:?}: {ids:?}");
    }

    #[test]
    fn a_repeated_cookie_name_quotes_each_value() {
        use crate::test_helpers::make_test_transaction_with_response;
        let tx = make_test_transaction_with_response(
            200,
            &[
                ("set-cookie", "is_gdpr_b=CPLgFhD1nAMoAg==; Path=/"),
                ("set-cookie", "other=1"),
                ("set-cookie", "is_gdpr_b=CPLgFhD1nAM=; Path=/"),
            ],
        );
        let rule = CookieAttributeConsistent;
        let found = crate::test_helpers::run_rule_all(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        let v = found
            .iter()
            .find(|v| v.violation == "cookie_name_duplicated")
            .expect("is_gdpr_b set twice");
        assert_eq!(
            v.message,
            "The response sets cookie 'is_gdpr_b' on 2 Set-Cookie lines, with the values 'CPLgFhD1nAMoAg==', 'CPLgFhD1nAM='"
        );
    }

    /// The value is quoted as written: an octet above %x7F that `str::trim`
    /// would take for whitespace stays in it.
    #[test]
    fn a_repeated_cookie_name_keeps_the_octets_of_its_values() -> anyhow::Result<()> {
        use crate::test_helpers::make_test_transaction_with_response;
        use hyper::header::HeaderValue;
        let mut tx = make_test_transaction_with_response(200, &[("set-cookie", "a=2")]);
        let headers = &mut tx.response.as_mut().unwrap().headers;
        let first = headers.remove("set-cookie").unwrap();
        headers.append("set-cookie", HeaderValue::from_bytes(b"a=1\xa0")?);
        headers.append("set-cookie", first);
        let rule = CookieAttributeConsistent;
        let found = crate::test_helpers::run_rule_all(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        let v = found
            .iter()
            .find(|v| v.violation == "cookie_name_duplicated")
            .expect("a set twice");
        assert!(v.message.contains("'1\u{a0}', '2'"), "{}", v.message);
        Ok(())
    }

    /// An octet `str::trim` takes for whitespace and § 5.2's WSP does not is
    /// part of the segment it ends or starts, and draws what it would draw
    /// anywhere else in it.
    #[rstest]
    #[case::value_tail(b"a=1\xa0", "cookie_value_character_forbidden")]
    #[case::value_tail_x85(b"a=1\x85", "cookie_value_character_forbidden")]
    #[case::name_lead(b"\xa0a=1", "token_character_forbidden")]
    fn an_obs_text_octet_at_a_segment_edge_is_read(
        #[case] line: &[u8],
        #[case] expected: &str,
    ) -> anyhow::Result<()> {
        use crate::test_helpers::make_test_transaction_with_response;
        use hyper::header::HeaderValue;
        let mut tx = make_test_transaction_with_response(200, &[]);
        tx.response
            .as_mut()
            .unwrap()
            .headers
            .append("set-cookie", HeaderValue::from_bytes(line)?);
        let rule = CookieAttributeConsistent;
        let ids: Vec<String> = crate::test_helpers::run_rule_all(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
        .into_iter()
        .map(|v| v.violation)
        .collect();
        assert!(ids.iter().any(|i| i == expected), "{line:?}: {ids:?}");
        Ok(())
    }

    #[test]
    fn max_age_negative_is_accepted() {
        let v = check_set_cookie("SID=1; Max-Age=-10");
        assert!(v.is_none());
    }
}
