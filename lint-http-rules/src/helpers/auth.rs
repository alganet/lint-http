// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! The authentication framework's four helpers, and the one thing they share.
//!
//! RFC 9110 § 11 defines `challenge` and `credentials` out of one vocabulary —
//! an `auth-scheme`, then either a `token68` or a `#auth-param` list — and this
//! module reads all four sides of it: a challenge, a credentials value, and the
//! credentials of the two schemes whose own documents say what goes in the
//! `token68` (RFC 7617's `Basic`, RFC 6750's `Bearer`).
//!
//! **A production is not a field, and § 11 writes each of these two for two
//! fields.** [`CREDENTIALS_FIELDS`] and [`CHALLENGE_FIELDS`] are the lists, and
//! they exist because naming one field in a reader is how the proxy half of
//! § 11.7 came to be unread: the functions here take a *value*, so the field a
//! rule points them at was the rule's own choice and nothing checked it against
//! the document. Every rule reading one of these productions walks a list from
//! here and says which field it read.
//!
//! **Every function here answers with a named defect, and none returns a
//! sentence.** [`AuthDefect`], [`AuthorizationDefect`],
//! [`BasicCredentialsDefect`] and [`BearerTokenDefect`] each carry what their
//! finding needs and own its wording; the callers compose only the subject.
//! Two of them span the same octet complaint under different productions —
//! `AuthDefect::SchemeCharacter` and
//! `AuthDefect::ParameterNameCharacter` — which is the distinction the
//! `String`s could not draw and the reason the conversion was worth doing.
//!
//! **Every trim here is `OWS` and every split is `is_sp_or_htab`, and the two
//! have to stay matched.** The values reaching this module are read as the
//! octets a sender wrote, so `%xA0` arrives as a `char` that `str::trim` removes
//! and no `SP` in `auth-scheme 1*SP …` generates — a scheme padded with one
//! would have been trimmed into validity, and one written *inside* a challenge
//! would have separated two members the sender wrote as one. The pairing is the
//! invariant the paragraph below turns on: the trim must remove exactly the
//! characters the split matches, or the first part of the split can be empty
//! where the code proves it cannot.
//!
//! **Four unreachable branches came out of naming them, three of one shape.**
//! `validate_challenge_syntax`, `validate_authorization_syntax` and the
//! `Content-Range` parser in another module each trimmed a value, rejected it
//! for emptiness, split at the first whitespace, and then checked whether the
//! first part was empty — which by then it cannot be, because the trim
//! removes exactly the characters the split matches. Written once
//! and copied twice. A `Result<_, String>` hides that: a dead `return Err` is a
//! line, while a variant nothing constructs is a claim the module cannot back.
//! The fourth was `Basic`'s "decoded credentials empty", which needed base64's
//! arithmetic rather than a reading — zero octets come out of zero symbols.
//!
//! `split_and_group_challenges` answers with [`AuthDefect`] too, rather
//! than with a type of its own: it reads the same field value as
//! `validate_challenge_syntax`, one half each, and a caller that has to match
//! on two types to report one field is a split made for the reader's
//! convenience and not for the operator's. The remaining `Result<_, String>`s
//! are deliberate — `parse_auth_params` has two distinct defects and
//! `parse_nc_hex` one, and an enum with a single variant is a `bool` with
//! ceremony.

use crate::helpers::headers::trim_ows;
use crate::helpers::list::split_commas_respecting_quotes;
use base64::Engine;

/// One field carrying an authentication production, in the two spellings a
/// reader of it needs.
///
/// The map is keyed by the lowercase name and an operator reads the field back
/// in the casing its own document prints, so a reader that had only one string
/// would either miss the field or name it wrongly in the finding.
#[derive(Clone, Copy)]
pub struct AuthField {
    /// The name as RFC 9110 § 11 writes it. This is what a message says.
    pub shown: &'static str,
    /// The name the header map is keyed by.
    pub key: &'static str,
}

/// One challenge-and-answer exchange: the field a recipient demands
/// authentication in, the status that carries that demand, and the field the
/// client answers it with.
pub struct AuthExchange {
    /// `WWW-Authenticate` or `Proxy-Authenticate`.
    pub challenge: AuthField,
    /// The status § 11 says must carry at least one of that challenge.
    pub status: u16,
    /// `Authorization` or `Proxy-Authorization`.
    pub credentials: AuthField,
}

/// The two exchanges § 11 defines, and the source the two field lists below are
/// taken from.
///
/// **They are two exchanges and not one, which is what a reader joining a
/// credential to a challenge has to know.** A nonce an origin issued in a `401`
/// is not one a proxy issued in a `407`, and credentials answering one demand
/// say nothing about the other; a join that crossed them would read a correct
/// client as replaying a nonce it was never offered.
///
// cite(RFC 9110 § 11.7.1): "A proxy MUST send at least one Proxy-Authenticate header field in each 407 (Proxy Authentication Required) response that it generates."
pub const AUTH_EXCHANGES: [AuthExchange; 2] = [
    AuthExchange {
        challenge: AuthField {
            shown: "WWW-Authenticate",
            key: "www-authenticate",
        },
        status: 401,
        credentials: AuthField {
            shown: "Authorization",
            key: "authorization",
        },
    },
    AuthExchange {
        challenge: AuthField {
            shown: "Proxy-Authenticate",
            key: "proxy-authenticate",
        },
        status: 407,
        credentials: AuthField {
            shown: "Proxy-Authorization",
            key: "proxy-authorization",
        },
    },
];

/// The request fields whose value *is* `credentials`.
///
/// § 11.6.2 and § 11.7.2 write the same production for two recipients — an
/// origin and the next inbound proxy — and neither section says anything about
/// the value that the other does not. A rule reading what a client presented
/// reads both, because the two are one sender's credentials addressed to
/// different hops, and a defect in either is that sender's to correct.
///
// cite(RFC 9110 § 11.7.2): "Its value consists of credentials containing the authentication information of the client for the proxy and/or realm of the resource being requested."
pub const CREDENTIALS_FIELDS: [AuthField; 2] =
    [AUTH_EXCHANGES[0].credentials, AUTH_EXCHANGES[1].credentials];

/// Every line of every field § 11 writes as `credentials`, each paired with the
/// name a finding about it has to say.
///
/// The production is one value rather than a list, so the lines are **not**
/// combined: a sender wrote each, and that a request carries more than one line
/// of a field is `singleton_fields_not_repeated`'s finding rather than a reason
/// to pick one line to believe. The octets come back as written, which is the
/// reading every caller wants and used to spell for itself.
pub fn credentials_field_lines(
    headers: &hyper::HeaderMap,
) -> impl Iterator<Item = (&'static str, String)> + '_ {
    CREDENTIALS_FIELDS.into_iter().flat_map(move |field| {
        headers.get_all(field.key).into_iter().map(move |hv| {
            (
                field.shown,
                crate::helpers::headers::field_line_as_written(hv),
            )
        })
    })
}

/// The response fields whose value is `#challenge`.
///
/// § 11.6.1 and § 11.7.1 write the same list of the same production, and
/// § 11.7.1 closes by saying so in a sentence rather than leaving it to be
/// inferred from the ABNF. The difference between the two fields is who the
/// challenge addresses, which decides what an *absent* one means and not what
/// a present one has to derive from.
///
// cite(RFC 9110 § 11.7.1): "Note that the parsing considerations for WWW-Authenticate apply to this header field as well"
pub const CHALLENGE_FIELDS: [AuthField; 2] =
    [AUTH_EXCHANGES[0].challenge, AUTH_EXCHANGES[1].challenge];

/// The whitespace `auth-scheme 1*SP …` prints, and the only whitespace a field
/// value carries beside its content.
///
/// `char::is_whitespace` is what this replaced, and it matches `%xA0` — an
/// `obs-text` octet a sender writes *inside* a value, which as a separator
/// would cut one member into two and as padding would be trimmed away. `SP` is
/// what the grammar writes; `HTAB` is admitted with it because
/// [`trim_ows`] takes both and the two must match.
fn is_sp_or_htab(c: char) -> bool {
    c == ' ' || c == '\t'
}

/// Split `auth-scheme` from what follows it, as `credentials` and `challenge`
/// both write it.
///
/// `credentials = auth-scheme [ 1*SP ( token68 / #auth-param ) ]`, and the
/// separator is `1*SP` — `HTAB` rides along with it because [`trim_ows`] takes
/// both and a splitter and a trimmer that disagree are worse than either. The
/// `OWS` comes off both ends of the value first — § 5.5 puts it outside the
/// field value — so the tail is `None` exactly when the trimmed value holds no
/// separator, which is a `credentials` of scheme alone and a legal one.
/// `Some("")` cannot come back: a trailing separator is `OWS` and is gone
/// before the split, so "scheme alone" and "scheme then whitespace" are one
/// field value here, which is what § 5.5 says they are.
///
/// **Why this is a function.** Six callers wrote
/// `value.splitn(2, char::is_whitespace)` with a `str::trim` on one side or
/// both. Three of them read the value through `to_str`, which refuses
/// everything outside HTAB and %x20-%x7E, so Rust's predicate and the grammar
/// agree there and nothing was wrong. The other three read it through
/// [`credentials_field_lines`], which is one `char` per octet — and there
/// `char::is_whitespace` is true of %x85 and %xA0, which are `obs-text`. Those
/// three split a credential at an octet that is not a separator and trimmed
/// away an octet that is not padding, so `Bearer abcdef<%xA0>` was cut down to
/// a conforming `b64token` and reported as nothing at all.
///
/// A trim that shortens a value is the worst failure available to a reader,
/// because it does not misreport: it repairs, and then the shortened value
/// passes every check that follows honestly.
///
/// cite(RFC 9110 § 11.4): "credentials = auth-scheme [ 1*SP ( token68 / #auth-param ) ]"
pub fn split_scheme_and_tail(value: &str) -> (&str, Option<&str>) {
    let mut parts = trim_ows(value).splitn(2, is_sp_or_htab);
    let scheme = parts
        .next()
        .expect("splitn always yields at least one element");
    (trim_ows(scheme), parts.next().map(trim_ows))
}

/// Split a WWW-Authenticate header value into "assembled" challenges.
///
/// This function splits top-level comma-separated members (respecting quoted-strings)
/// and groups members into challenges: a member that begins with an auth-scheme
/// (token followed by whitespace or end-of-member) starts a new challenge; subsequent
/// members without a leading scheme are treated as continuation parameters for
/// the current challenge.
///
/// Returns the challenges, and beside them the [`AuthDefect`]s of the list
/// itself: an empty member, or a parameter with no challenge before it. There
/// was a third — *missing scheme on a member that starts with whitespace* — and
/// it was the same problem read off a character the list grammar puts outside
/// the element.
///
/// **Neither ends the reading.** This returned the first as an `Err` and no
/// challenge was read at all, so `Basic realm="a", , Bearer error=` said only
/// that a member was empty. § 5.6.1.2 has a recipient parse and ignore an empty
/// element, so the value splits into members as well as any other, and an
/// `auth-param` arriving before any scheme belongs to no challenge and is set
/// aside with the defect saying so. Each is reported once per value, since
/// neither sentence names a member.
///
/// The two it can answer with are the list's rather than one challenge's, and
/// they are variants of the same type as the rest because a caller reports them
/// the same way: this function and [`validate_challenge_syntax`] are two halves
/// of reading one field value.
// cite(RFC 9110 § 5.6.1.2): "A recipient MUST parse and ignore a reasonable number of empty list elements:"
pub fn split_and_group_challenges(s: &str) -> (Vec<String>, Vec<AuthDefect<'_>>) {
    let members: Vec<&str> = split_commas_respecting_quotes(s);
    let mut challenges: Vec<String> = Vec::new();
    let mut defects: Vec<AuthDefect<'_>> = Vec::new();

    for m in members {
        // The `OWS` the `#rule` prints around its commas is the splitter's to
        // remove, and it removes exactly that — the `str::trim` this replaced
        // also took %xA0 and %x85 off a member's ends, which are `obs-text` and
        // are two of the octets the `auth-scheme` check below exists to name.
        let mm = m;
        if mm.is_empty() {
            if !defects.contains(&AuthDefect::EmptyMember) {
                defects.push(AuthDefect::EmptyMember);
            }
            continue;
        }

        // A member that is a `token`, optional whitespace and then `=` is an
        // `auth-param` with `BWS` before its delimiter, and nothing else:
        // `challenge` puts `1*SP` after its scheme and then `token68` or an
        // `auth-param`, and neither begins with `=`. Reading the token before
        // the whitespace as a scheme made `, algorithm = SHA-256` a second
        // challenge named `algorithm` with an empty-named parameter. A first
        // member has no challenge to continue, so `Basic =x` is still read as a
        // scheme followed by what it fails to be.
        // cite(RFC 9110 § 11.2): "auth-param     = token BWS "=" BWS ( token / quoted-string )"
        let name_end = mm
            .find(|c: char| !crate::helpers::token::is_tchar(c))
            .unwrap_or(mm.len());
        let param_with_bws =
            name_end > 0 && name_end < mm.len() && trim_ows(&mm[name_end..]).starts_with('=');
        let is_new = !(param_with_bws && !challenges.is_empty()) && {
            let s = mm;
            if let Some(idx) = s.find(is_sp_or_htab) {
                let scheme = trim_ows(&s[..idx]);
                crate::helpers::token::find_invalid_token_char(scheme).is_none()
            } else if s.contains('=') {
                false
            } else {
                crate::helpers::token::find_invalid_token_char(s).is_none()
            }
        };

        if is_new {
            challenges.push(mm.to_string());
        } else if let Some(last) = challenges.last_mut() {
            last.push_str(", ");
            last.push_str(mm);
        } else {
            // A continuation with no challenge before it. There used to be two
            // messages here, chosen by whether the member as split began with
            // whitespace — and that was the `OWS` of `#challenge`'s own comma
            // separator being read as evidence about the challenge. ` realm="x"`
            // and `realm="x"` are the same member: §5.6.1.1 puts the whitespace
            // outside the element, so after it is removed there is one case and
            // one thing to say about it.
            // cite(RFC 9110 § 11.6.1): "WWW-Authenticate = #challenge"
            // cite(RFC 9110 § 5.6.1.1): "1#element => element *( OWS "," OWS element )"
            if !defects.contains(&AuthDefect::SchemeMissing) {
                defects.push(AuthDefect::SchemeMissing);
            }
        }
    }

    (challenges, defects)
}

/// What a value written as an `auth-scheme` and whatever § 11.2 allows after it
/// fails to be.
///
/// **Named for the framework and not for a side, because § 11.3 and § 11.4
/// write the same production.** `challenge = auth-scheme [ 1*SP ( token68 /
/// #auth-param ) ]` and `credentials = auth-scheme [ 1*SP ( token68 /
/// #auth-param ) ]` are one grammar under two names, so a `WWW-Authenticate`
/// and an `Authorization` fail to be it in the same ways and
/// [`validate_scheme_tail`] answers for both. The type was called
/// `ChallengeDefect` while one side read it, which made the second reader's
/// findings look like they were about a challenge that was not in the message.
///
/// Two variants are the *list's* and reach this from the challenge side only:
/// [`EmptyMember`](Self::EmptyMember) and [`SchemeMissing`](Self::SchemeMissing)
/// are `#challenge`'s, found while the members were being grouped, and
/// `credentials` is one value with no list around it.
///
/// The rest split by *what was being read*, which is the only way they group:
/// the `auth-scheme`, the `token68` alternative, and the `#auth-param` one. Two
/// variants that look alike belong to different halves of that —
/// [`SchemeCharacter`](Self::SchemeCharacter) and
/// [`ParameterNameCharacter`](Self::ParameterNameCharacter) both report a
/// non-`token` octet, and the production each read it under is the difference.
///
/// [`SuspiciousSingleToken`](Self::SuspiciousSingleToken) is the one variant
/// that is not a grammar failure and says so in its name. `token68` admits a
/// bare word, so `NewSch abcd` is well-formed by § 11.2; what this reports is
/// that it is *indistinguishable* from an `auth-param` someone forgot the value
/// of. Naming it keeps that heuristic from reading as a syntax verdict — the
/// `String` this replaced made it one sentence among the rest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthDefect<'a> {
    /// An empty member of `WWW-Authenticate = #challenge`, found while the
    /// members were being grouped. There is no second variant for a challenge
    /// that is empty once assembled, because a challenge is a member: the
    /// grouping refuses every empty one before anything is assembled from it.
    EmptyMember,
    /// A member that continues a challenge with no challenge before it: an
    /// `auth-param` arriving where the list has not yet had an `auth-scheme`.
    SchemeMissing,
    /// A non-`token` octet in the `auth-scheme`, carrying the character.
    SchemeCharacter(char),
    /// A control octet where a `token68` was read. `token68`'s alphabet is
    /// ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" and its padding, and a
    /// control octet is in none of it.
    Token68ControlCharacter,
    /// A single bare word after the scheme that is a `token68` by the grammar
    /// and a value-less `auth-param` by eye. Carries the word.
    SuspiciousSingleToken(&'a str),
    /// A member whose name is empty — `=x`, which has a value and nothing it
    /// belongs to. Carries the member as written, because a challenge can hold
    /// two and the finding has to say which.
    EmptyParameterName(&'a str),
    /// An `auth-param` written without its `=` at all, carrying the word that
    /// was there. `auth-param` is `token BWS "=" BWS ( token / quoted-string )`
    /// and nothing brackets the delimiter, so a bare word among the parameters
    /// derives from the production not at all.
    ParameterEqualsMissing(&'a str),
    /// An `auth-param` whose `=` is written and whose value is not, carrying the
    /// name. Both alternatives after the delimiter have a floor of one
    /// character, so neither derives the empty value.
    ///
    /// **Split from [`ParameterEqualsMissing`](Self::ParameterEqualsMissing),
    /// which one variant used to answer for as well.** The two are different
    /// mistakes — a name written as though it were a flag, and a value written
    /// as though it were optional — and a sender told only "missing value"
    /// cannot tell which of them it made.
    ParameterValueEmpty(&'a str),
    /// A member of the `#auth-param` list with nothing in it: a doubled comma,
    /// or one at either end.
    ///
    /// **Reachable from the credentials side only, and that is why it exists.**
    /// On the challenge side [`split_and_group_challenges`] has already refused
    /// every empty member before a challenge is assembled, and the parameter
    /// walk below was written under that guarantee. `credentials` has no list
    /// around it, so nothing has looked at its members before the walk does, and
    /// the guarantee the walk was leaning on is not one its second caller can
    /// make.
    ParameterMemberEmpty,
    /// A non-`token` octet in an `auth-param` name, carrying the name as
    /// written and the character.
    ParameterNameCharacter {
        /// The name, as the sender wrote it.
        name: &'a str,
        /// The first octet `token` does not admit.
        character: char,
    },
    /// A non-`token` octet in an unquoted `auth-param` value, carrying the
    /// parameter it belonged to and the character. The name is what tells two
    /// of these apart in one challenge.
    ParameterValueCharacter {
        /// The `auth-param` name the bad value belonged to.
        name: &'a str,
        /// The first octet `token` does not admit.
        character: char,
    },
    /// A value that opens with a DQUOTE and is not a well-formed
    /// `quoted-string`. Carries the parameter it belonged to, the value as
    /// written, and the [`QuotedStringDefect`](crate::helpers::quoted_string::QuotedStringDefect) — the reason this
    /// conversion needed the typed answer from that module, since the finding
    /// names the parameter and the defect names the value.
    ParameterQuotedValue {
        /// The `auth-param` name the bad value belonged to.
        name: &'a str,
        /// The value as written, DQUOTEs included.
        value: &'a str,
        /// What it failed to be.
        defect: crate::helpers::quoted_string::QuotedStringDefect,
    },
    /// One `auth-param` name written more than once in one challenge, carrying
    /// the name as the second occurrence spelled it.
    ///
    /// **The second variant here that is not a defect of the grammar**:
    /// `#auth-param` derives `realm=a, realm=b` as readily as any other list of
    /// two, so it is counted over the well-formed members only, which is what
    /// its sentence says of them.
    ///
    /// **Challenge-side only, because the sentence counts per challenge.** A
    /// `credentials` value is not a challenge and § 11.4 gives it no unit to
    /// count within, so this is one of the two things [`Side`] decides.
    ParameterDuplicated(&'a str),
    /// A `realm` written as a `token` where § 11.5 admits only the
    /// `quoted-string`. Carries the value as written.
    ///
    /// **Not a defect of the grammar**, and read only for a member that is
    /// otherwise well formed, so one member never carries this and a grammar
    /// finding both. It used to wait until every member of the challenge was
    /// clean, which hid it behind a defect in some other member entirely.
    RealmUnquoted(&'a str),
    /// Whitespace beside an `auth-param`'s `=`, carrying the member as written.
    ///
    /// Read for a well-formed member, like the two above: `auth-param` prints
    /// `BWS` there, so the member derives, and a recipient is required to
    /// remove the octets and read what is left. What refuses them is § 5.6.3's
    /// requirement on the sender.
    ParameterBws(&'a str),
}

impl AuthDefect<'_> {
    /// The finding, about the field that carried the challenge.
    ///
    /// **The field is an argument because the production is not the field's.**
    /// `challenge` is § 11.3's, and `WWW-Authenticate` and `Proxy-Authenticate`
    /// are two lists of it — § 11.7.1 defines the second in the first's terms
    /// and differs only in who the challenge addresses. The ids these render
    /// under never named a field, so a second reader needed no new entry; the
    /// sentences did name one, in every arm, and this is what that cost.
    ///
    /// Callers pass the field as a sender spells it, because that is how a
    /// reader will find it in the message they are holding.
    // cite(RFC 9110 § 11.7.1): "The "Proxy-Authenticate" header field consists of at least one challenge that indicates the authentication scheme(s) and parameters applicable to the proxy for this request."
    pub fn message(self, field: &str) -> String {
        match self {
            Self::EmptyMember => {
                format!("{field} header contains empty challenge/member")
            }
            Self::SchemeMissing => {
                format!("{field} contains parameter before any auth-scheme")
            }
            Self::SchemeCharacter(c) => {
                format!("Invalid character '{c}' in {field} auth-scheme")
            }
            Self::Token68ControlCharacter => {
                format!("{field} token68 contains control characters")
            }
            Self::SuspiciousSingleToken(word) => format!(
                "{field} challenge carries the single word '{word}' after its scheme, and the grammar refuses nothing about it: `token68` derives that word, and so does an `auth-param` whose value was left off, so the value cannot say which of the two was written"
            ),
            Self::EmptyParameterName(member) => format!(
                "{field} auth-param name is empty in '{}'",
                crate::helpers::shown::shown_in_finding(member)
            ),
            Self::ParameterEqualsMissing(name) => {
                format!("{field} auth-param '{name}' is written without its '='")
            }
            Self::ParameterValueEmpty(name) => {
                format!("{field} auth-param '{name}' has nothing after its '='")
            }
            Self::ParameterMemberEmpty => {
                format!("{field} auth-param list has an empty member")
            }
            // These three take the field and used to drop it. A
            // `Proxy-Authenticate` finding read "Invalid character '@' in
            // auth-param name" with nothing in it saying which of the four
            // fields carrying this production had been read, which is the whole
            // reason the argument is here.
            Self::ParameterNameCharacter { name, character } => format!(
                "Invalid character '{character}' in {field} auth-param name '{}'",
                crate::helpers::shown::shown_in_finding(name)
            ),
            Self::ParameterValueCharacter { name, character } => format!(
                "Invalid character '{character}' in {field} auth-param value for '{}'",
                crate::helpers::shown::shown_in_finding(name)
            ),
            Self::ParameterQuotedValue {
                name,
                value,
                defect,
            } => format!(
                "Invalid quoted-string in {field} auth-param '{}': {}",
                name,
                defect.message(value)
            ),
            Self::ParameterDuplicated(name) => format!(
                "{field} names the '{name}' parameter more than once in one challenge, and RFC 9110 \u{a7}11.2 admits it once (\"each parameter name MUST only occur once per challenge\") \u{2014} both values are well formed, so what the challenge means by '{name}' is whichever one the recipient happens to keep"
            ),
            Self::RealmUnquoted(value) => format!(
                "{field} writes its realm as the token '{}', and RFC 9110 \u{a7}11.5 admits only the quoted-string syntax for it (\"For historical reasons, a sender MUST only generate the quoted-string syntax\") \u{2014} write realm=\"{}\" instead",
                crate::helpers::shown::shown_in_finding(value),
                value
            ),
            Self::ParameterBws(member) => format!(
                "{field} auth-param '{}' has whitespace around its '='; the grammar admits BWS there only for historical reasons",
                crate::helpers::shown::shown_in_finding(member)
            ),
        }
    }
}

/// How many `"="` close a value that derives from `token68`, or `None` where
/// the production does not derive it at all.
///
/// **The padding is inside the alternative.** `token68` is one or more octets
/// from its own alphabet followed by `*"="`, so the `=` on a base64 credential
/// belongs to the credential and is not a separator between anything. A reader
/// that decides between `token68` and `#auth-param` by asking whether an `=`
/// is present anywhere is asking about a character both alternatives contain.
///
/// The count is what the caller needs rather than a yes: one padding octet
/// leaves a value both alternatives derive, and more than one leaves a value
/// only this one does.
// cite(RFC 9110 § 11.2): "token68    = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"=""
fn token68_padding(value: &str) -> Option<usize> {
    let body = value.trim_end_matches('=');
    if body.is_empty()
        || !body
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~' | '+' | '/'))
    {
        return None;
    }
    Some(value.len() - body.len())
}

/// Every way one assembled `WWW-Authenticate` challenge fails § 11.3, as
/// [`AuthDefect`]s in the order the members were written; empty when it
/// conforms.
///
/// **A challenge cannot fail to have an `auth-scheme` here, and the branch that
/// said it could is gone.** The value is trimmed and checked for emptiness
/// first, so it opens with a non-whitespace character; the scheme is everything
/// before the first `is_sp_or_htab`, which is therefore non-empty, and
/// `str::trim` removes exactly that same set so it cannot empty it either. The
/// old `"challenge missing auth-scheme"` string was unreachable, and only became
/// visible when the failures had to be enumerated as variants — an enum with a
/// variant nothing constructs is a claim the module cannot back. What the test
/// named `validate_missing_scheme_error` actually exercises is a leading-space
/// member whose scheme reads as `realm="x"` and fails on the `=`.
pub fn validate_challenge_syntax(challenge: &str) -> Vec<AuthDefect<'_>> {
    let c = trim_ows(challenge);
    // The caller has already refused this. `split_and_group_challenges` returns
    // `EmptyMember` for any member that is empty after the splitter's `OWS`
    // trim, so every string it assembles is non-empty and a continuation is
    // joined onto one that already was. The branch stays anyway, and reports
    // the live id the value would be rather than a variant of its own: an
    // `Err` nothing constructs is a claim this module cannot back, and a
    // silent `Ok` on a value no caller sends today is a claim it cannot back
    // tomorrow.
    // cite(RFC 9110 § 11.3): "challenge   = auth-scheme [ 1*SP ( token68 / #auth-param ) ]"
    if c.is_empty() {
        return vec![AuthDefect::SchemeMissing];
    }
    // A challenge is a member of a list, so its `#auth-param` members have
    // already been through `split_and_group_challenges`. `Side::Challenge` is
    // the other half of what makes this side different: a bare word here may be
    // a `realm` whose value was left off, and that is a judgment about a
    // challenge rather than about the grammar.
    validate_scheme_tail(c, Side::Challenge, MemberEmptiness::AlreadyRefused)
}

/// Which side of § 11.2's framework wrote the value being read.
///
/// **Two constructs after the scheme are derived by `token68` *and* by
/// `#auth-param`, and neither can be settled from the octets.** A single bare
/// word is a `token68` and is equally an `auth-param` whose value was left off;
/// a word ending in one `=` is a `token68` with a padding octet and is equally
/// an `auth-param` written with its `=` and nothing after it. § 11.3 and § 11.4
/// print the same right-hand side, so the grammar does not choose — what
/// chooses is which side wrote it, because that is what says which alternative
/// the sender was reaching for.
///
/// A challenge exists to hand a client parameters, so a word where `realm="x"`
/// belongs is a plausible mistake. Credentials are the other way round: a
/// `token68` is what `Negotiate`, `NTLM`, `DPoP`, `Basic` and `Bearer` write
/// there, and nothing is missing from it.
///
/// **This was `Ambiguity`, and the name was the defect.** It answered one of
/// the two ambiguities and was named after the answer, so the branch reading a
/// padded value had no way to ask the same question and decided by a list of
/// three scheme names instead — with no direction on it, and therefore wrong
/// for two of the three in one of the two directions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// `WWW-Authenticate` or `Proxy-Authenticate`: the server offering a
    /// challenge, whose § 11.3 tail is the parameters it wants back.
    Challenge,
    /// `Authorization` or `Proxy-Authorization`: the client presenting
    /// credentials, whose § 11.4 tail is whatever the scheme defines.
    Credentials,
}

/// Whether the caller has already refused the empty members of the
/// `#auth-param` list.
///
/// The parameter walk below was written under a guarantee that only one of its
/// two callers can make. `split_and_group_challenges` splits a
/// `WWW-Authenticate` on the same commas first and returns
/// [`AuthDefect::EmptyMember`] for any member with nothing in it, so a challenge
/// reaching the walk has none left; `credentials` has no list around it, and
/// nothing has looked at its commas before the walk does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberEmptiness {
    /// The caller refused them, and the walk will not meet one.
    AlreadyRefused,
    /// Nothing has looked yet, and the walk reports its own.
    ReadHere,
}

/// The part of § 11.2's framework that follows an `auth-scheme`, read for
/// whichever field carried it.
///
/// **§ 11.3 and § 11.4 write this identically**, so `WWW-Authenticate`,
/// `Proxy-Authenticate`, `Authorization` and `Proxy-Authorization` are one
/// grammar under four names and this is the one reading of it. It was the
/// challenge reader's second half for as long as only challenges were read that
/// far: the request side asked whether the credentials were non-empty and held
/// no control octet and stopped, so `Authorization: Custom realm="x", , q="1"`
/// drew nothing where the same value in `WWW-Authenticate` drew a finding.
///
/// The `scheme` argument is read and not just skipped: one branch below turns on
/// whether it is a scheme whose own document is in this crate.
// cite(RFC 9110 § 11.3): "challenge   = auth-scheme [ 1*SP ( token68 / #auth-param ) ]"
// cite(RFC 9110 § 11.4, label: credentials grammar): "credentials = auth-scheme [ 1*SP ( token68 / #auth-param ) ]"
pub fn validate_scheme_tail(
    value: &str,
    side: Side,
    members: MemberEmptiness,
) -> Vec<AuthDefect<'_>> {
    // The three `token68` readings below share this: the alternative's alphabet
    // has no control octet in it, whichever way the value reached the branch.
    let has_control = |s: &str| s.chars().any(|c| (c as u32) < 0x20 || c == '\x7f');

    // scheme is first token before whitespace -- through the shared splitter, so
    // the challenge side and the credentials side cut at the same octets.
    // cite(RFC 9110 § 11.3): "challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]"
    //
    // The scheme and what follows it are two productions, and a defect in the
    // first does not stop the second being read: the split is at the first
    // `1*SP` whatever the scheme holds, so the tail is the same octets either
    // way and each is its own repair.
    let (scheme, tail) = split_scheme_and_tail(value);
    let mut out = Vec::new();
    if let Some(invalid) = crate::helpers::token::find_invalid_token_char(scheme) {
        out.push(AuthDefect::SchemeCharacter(invalid));
    }

    if let Some(rest) = tail {
        if rest.is_empty() {
            return out;
        }

        // `token68` closes with `*"="`, and the routing below reads an `=`
        // anywhere in the rest as the mark of an `auth-param`. That sends a
        // padded credential to the parameter parser, which finds the second
        // padding octet where a value goes and reports it as a character no
        // value admits -- `Negotiate <base64>==`, which is how SPNEGO writes a
        // challenge, was an `error` about a value the grammar generates.
        //
        // **Only more than one padding octet is settled here.** `abc=` is
        // derived by both alternatives -- a `token68` and an `auth-param` whose
        // value was left off -- and the branch below already decides that one
        // by the scheme. Two or more cannot be an `auth-param` at all: a value
        // is `token / quoted-string` and `=` is in neither, so nothing is being
        // chosen between and the production answers alone.
        //
        // No control octet is possible on this path: the alphabet
        // `token68_padding` matches holds none, so the reading that guards the
        // branches around it has nothing left to ask.
        // cite(RFC 9110 § 11.2): "auth-param     = token BWS "=" BWS ( token / quoted-string )"
        if token68_padding(rest).is_some_and(|padding| padding > 1) {
            return out;
        }

        if !rest.contains('=') {
            if has_control(rest) {
                out.push(AuthDefect::Token68ControlCharacter);
            } else if side == Side::Challenge
                && !rest
                    .chars()
                    .any(|ch| matches!(ch, '+' | '/' | '=' | '.' | '-' | '_'))
            {
                out.push(AuthDefect::SuspiciousSingleToken(rest));
            }
            return out;
        }

        // rest contains '='; decide heuristics
        let first_part = trim_ows(rest.split('=').next().unwrap_or(""));
        let after_eq = trim_ows(rest.split_once('=').map(|x| x.1).unwrap_or(""));
        let first_invalid = crate::helpers::token::find_invalid_token_char(first_part).is_some();
        if !rest.contains(',') {
            if first_invalid && !after_eq.starts_with('"') {
                if has_control(rest) {
                    out.push(AuthDefect::Token68ControlCharacter);
                }
                return out;
            }

            if rest.ends_with('=') && after_eq.is_empty() {
                // **The second construct both alternatives derive, and it is
                // settled the way the bare word above it is: by the side.**
                // `dXNlcjpwYXNzMTI=` is a `token68` whose last octet is the
                // `*"="` the production closes with, and it is equally an
                // `auth-param` named `dXNlcjpwYXNzMTI` written with its `=` and
                // no value. Nothing in § 11.2 chooses between them.
                //
                // A scheme's own document does choose, but only for the side it
                // is talking about, and the list here had no side on it. RFC
                // 7617 § 2 writes `Basic`'s challenge as `realm` and `charset`
                // auth-params and its credentials as the base64 `token68` of a
                // `user-pass`; RFC 6750 splits the same way, § 3 auth-params for
                // the challenge and § 2.1's `b64token` for the credentials. Only
                // `Digest` writes `#auth-param` in both directions — RFC 7616
                // gives it no `token68` form at all — so it is the one name that
                // decides without a side.
                //
                // Reading the three without the side made an ordinary Basic
                // credential an `error`: `Authorization: Basic dXNlcjpwYXNzMTI=`
                // is `user:pass12`, and about a third of all base64 closes on
                // exactly one padding octet.
                // cite(RFC 9110 § 11.2): "token68    = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"=""
                let scheme_writes_params = scheme.eq_ignore_ascii_case("digest")
                    || (side == Side::Challenge
                        && (scheme.eq_ignore_ascii_case("basic")
                            || scheme.eq_ignore_ascii_case("bearer")));
                if !scheme_writes_params {
                    if has_control(rest) {
                        out.push(AuthDefect::Token68ControlCharacter);
                    }
                    return out;
                }

                out.push(AuthDefect::ParameterValueEmpty(first_part));
                return out;
            }
        }

        out.extend(auth_param_list(rest, scheme, side, members));
    }

    out
}

/// One `auth-param` member as written: the name with its trailing `BWS`, the
/// name, what follows the `=` with its leading `BWS`, and the value.
struct AuthParamMember<'a> {
    name_written: &'a str,
    name: &'a str,
    val: &'a str,
    value: &'a str,
}

/// One member of an `#auth-param` list read against the production, answered
/// with its parts or with the first thing it fails to be.
///
/// **One member, one finding.** The checks read the name, then the `=`, then
/// the value, and a member that fails an earlier one has nothing the later ones
/// could be about: a member with no `=` has no value to judge. This is the
/// funnel inside [`auth_param_list`]'s walk, and returning here is returning
/// from one member and not from the list.
// cite(RFC 9110 § 11.2): "auth-param     = token BWS "=" BWS ( token / quoted-string )"
fn auth_param_member(param: &str) -> Result<AuthParamMember<'_>, AuthDefect<'_>> {
    let mut kv = param.splitn(2, '=');
    let name_written = kv
        .next()
        .expect("splitn always yields at least one element");
    let name = trim_ows(name_written);
    if name.is_empty() {
        return Err(AuthDefect::EmptyParameterName(trim_ows(param)));
    }
    // The `=` and the value after it are two things a sender leaves out,
    // and one variant used to answer for both. A member with no `=` in
    // it derives from `auth-param` not at all; a member with an `=` and
    // nothing after it broke the floor of the two alternatives.
    let Some(val) = kv.next() else {
        return Err(AuthDefect::ParameterEqualsMissing(name));
    };
    if let Some(character) = crate::helpers::token::find_invalid_token_char(name) {
        return Err(AuthDefect::ParameterNameCharacter { name, character });
    }
    let value = trim_ows(val);
    if value.is_empty() {
        return Err(AuthDefect::ParameterValueEmpty(name));
    }
    if value.starts_with('"') {
        if let Err(defect) = crate::helpers::quoted_string::check_quoted_string(value) {
            return Err(AuthDefect::ParameterQuotedValue {
                name,
                value,
                defect,
            });
        }
    } else if let Some(character) = crate::helpers::token::find_invalid_token_char(value) {
        return Err(AuthDefect::ParameterValueCharacter { name, character });
    }
    Ok(AuthParamMember {
        name_written,
        name,
        val,
        value,
    })
}

/// Every defect of an `#auth-param` list, the part of § 11.2's framework
/// [`validate_scheme_tail`] reaches once the tail is known to be one.
fn auth_param_list<'a>(
    rest: &'a str,
    scheme: &str,
    side: Side,
    members: MemberEmptiness,
) -> Vec<AuthDefect<'a>> {
    let mut out = Vec::new();
    // Parse auth-params. The `OWS` around the `#auth-param` commas is the
    // splitter's; the `str::trim` this replaced also took the two `obs-text`
    // octets that look like whitespace, and no `token` admits either.
    // Whether an empty member is this walk's to report is the caller's
    // answer, and both answers are true of one of them: the challenge side's
    // commas have been through `split_and_group_challenges`, the credentials
    // side's have been through nothing.
    //
    // **Every member answers for itself.** `#auth-param` is a repetition
    // the sender wrote member by member, so a member that fails the
    // production is one repair and the member after it is another. This
    // walk returned at the first, and a challenge carrying two defects drew
    // one finding and then, once that was fixed, the other. What one
    // member yields is still one finding: the checks below read the name,
    // then the `=`, then the value, and a member that fails an earlier one
    // has nothing the later ones could be about.
    //
    // The empty member is counted once per value, because its sentence
    // names no member and two of them would be two identical lines.
    // cite(RFC 9110 § 5.6.1.1): "In any production that uses the list construct, a sender MUST NOT generate empty list elements."
    let mut empty_member_seen = false;

    // **A realm written as a `token` is not a defect of the production**,
    // which offers `token / quoted-string` and derives `realm=foo` as
    // readily as `realm="foo"`, and § 11.5's MUST is what refuses it. It
    // used to be held back until every member came through clean, on the
    // argument that reporting a historical spelling *in place of* a member
    // that fails the grammar would let the weakest claim mask the
    // strongest. Once every member answers, nothing is reported in place of
    // anything, and holding it back only hid it behind an unrelated member.
    // It is read for a member that is otherwise clean, so one member never
    // carries both this and a grammar finding.
    //
    // **The first realm and not the last**: a second one is the duplicate's
    // finding below, and which of the two a recipient keeps is exactly what
    // that finding says nobody can know.
    //
    // Where the scheme is `Digest`, RFC 7616 says this about `realm` in
    // both directions and reports it under its own entries — § 3.4 for a
    // credential, § 3.3 for a challenge — so the general reading declines
    // rather than putting a second finding on one value with one repair.
    //
    // **The guard was directed and is not any more**, which is worth saying
    // because the narrower version was correct when it was written: § 3.4's
    // reader walks `Authorization` and `Proxy-Authorization` and never a
    // response, so a challenge spelled `Digest realm=foo` really was this
    // reading's alone until § 3.3 gained one. A decline scoped to a
    // direction is a claim about which readers exist, and that is a fact
    // that moves.
    // cite(RFC 9110 § 11.5): "For historical reasons, a sender MUST only generate the quoted-string syntax."
    let realm_is_answered_elsewhere = scheme.eq_ignore_ascii_case("digest");
    let mut unquoted_realm: Option<&str> = None;

    // § 11.2's other MUST, counted over the members that are well formed,
    // because the sentence it renders says both values are: a name written
    // twice beside a malformed occurrence of itself is the malformed
    // member's finding. Each name once, however many times it repeats.
    //
    // **The scope is a challenge and not a field line.** `WWW-Authenticate`
    // is `#challenge` and § 11.6.1 prints two challenges each naming their
    // own `realm` as the ordinary case, so the count is taken here — inside
    // one assembled challenge, after `split_and_group_challenges` has
    // decided where the challenges are — and a walk that counted per field
    // value would report the specification's own example. On the
    // credentials side there is no challenge to count within: § 11.4 gives
    // `credentials` no list around it and states no sentence of its own, so
    // this is `Side`'s to decide and not the grammar's.
    //
    // The names are folded because the same sentence folds them.
    // cite(RFC 9110 § 11.2): "Authentication parameters are name/value pairs, where the name token is matched case-insensitively and each parameter name MUST only occur once per challenge."
    let mut seen: Vec<String> = Vec::new();
    let mut duplicated: Vec<&str> = Vec::new();

    // § 5.6.3's MUST NOT on the sender: `auth-param` prints `BWS` beside
    // its `=`, so the member derives and a recipient reads it with the
    // whitespace removed. Every well-formed member carrying it, since the
    // finding names the member.
    // cite(RFC 9110 § 5.6.3): "A sender MUST NOT generate BWS in messages."
    let mut bws: Vec<&str> = Vec::new();

    for param in split_commas_respecting_quotes(rest) {
        // OWS only: `str::trim` takes the octets %xA0 and %x85 for
        // whitespace, and a member holding one of them is not empty.
        if crate::helpers::headers::trim_ows(param).is_empty() {
            if members == MemberEmptiness::ReadHere && !empty_member_seen {
                empty_member_seen = true;
                out.push(AuthDefect::ParameterMemberEmpty);
            }
            continue;
        }
        let member = match auth_param_member(param) {
            Ok(member) => member,
            Err(defect) => {
                out.push(defect);
                continue;
            }
        };
        let AuthParamMember {
            name_written,
            name,
            val,
            value: v,
        } = member;
        if !v.starts_with('"')
            && unquoted_realm.is_none()
            && !realm_is_answered_elsewhere
            && name.eq_ignore_ascii_case("realm")
        {
            unquoted_realm = Some(v);
        }
        if name_written.ends_with(is_sp_or_htab) || val.starts_with(is_sp_or_htab) {
            bws.push(trim_ows(param));
        }
        if side == Side::Challenge {
            let folded = name.to_ascii_lowercase();
            if !seen.contains(&folded) {
                seen.push(folded);
            } else if !duplicated.iter().any(|d| d.eq_ignore_ascii_case(name)) {
                duplicated.push(name);
            }
        }
    }

    // A realm written twice has no single spelling to correct: which of the
    // two a recipient keeps is the duplicate's finding, and naming the
    // first one's spelling would send the sender to repair a value that
    // may not be the one in use. One subject, and the duplication is the
    // answer about it.
    let realm_duplicated = duplicated.iter().any(|d| d.eq_ignore_ascii_case("realm"));
    out.extend(duplicated.into_iter().map(AuthDefect::ParameterDuplicated));
    out.extend(
        unquoted_realm
            .filter(|_| !realm_duplicated)
            .map(AuthDefect::RealmUnquoted),
    );
    out.extend(bws.into_iter().map(AuthDefect::ParameterBws));
    out
}

/// What a `credentials` field value fails to be.
///
/// Five variants for a value read in three passes: the `auth-scheme`, the two
/// things this helper judges about what follows it, and then § 11.4's own
/// alternative. [`MissingCredentials`](Self::MissingCredentials) is the one
/// that is this helper's judgment rather than § 11.4's grammar — see
/// [`validate_authorization_syntax`], which explains why a bare scheme is
/// framework-valid and reported anyway.
///
/// [`Credentials`](Self::Credentials) is the production, and it is a wrapper
/// rather than a set of variants because the grammar it carries is not this
/// field's: § 11.4 writes `auth-scheme [ 1*SP ( token68 / #auth-param ) ]` and
/// § 11.3 writes it again for a challenge, so both sides fail to be it in the
/// same ways and [`validate_scheme_tail`] answers for both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationDefect<'a> {
    /// No field value.
    Empty,
    /// A non-`token` octet in the `auth-scheme`, carrying the character.
    SchemeCharacter(char),
    /// A scheme with nothing after it, or nothing but whitespace.
    MissingCredentials,
    /// A control octet other than HTAB in the credentials, read before the
    /// alternative is chosen. Both alternatives refuse it — `token68`'s
    /// alphabet holds no control octet and neither does a `token` or the
    /// `qdtext` of a `quoted-string` — so this is the one verdict about the
    /// value that does not need to know which of the two was written. HTAB is
    /// left to the production, because `#auth-param`'s `OWS` and `qdtext` both
    /// admit it.
    CredentialsControlCharacter,
    /// What § 11.4's `[ 1*SP ( token68 / #auth-param ) ]` failed to be, read by
    /// the same function that reads § 11.3's.
    Credentials(AuthDefect<'a>),
}

impl<'a> AuthorizationDefect<'a> {
    /// The finding, about the field that carried the credentials.
    ///
    /// **The field is an argument because the production is not the field's.**
    /// § 11.7.2 writes `Proxy-Authorization = credentials`, the same production
    /// § 11.6.2 writes for the origin's field, so one reader answers for both.
    /// These sentences named `Authorization` outright and the rule prefixed the
    /// field it had actually read, so a `Proxy-Authorization` finding read
    /// *"Invalid Proxy-Authorization header: Invalid character '@' in
    /// Authorization auth-scheme"* — the wrong field named inside the right one,
    /// and the origin's own findings naming theirs twice.
    ///
    /// Callers pass the field as a sender spells it, because that is how a
    /// reader will find it in the message they are holding.
    // cite(RFC 9110 § 11.7.2, label: Proxy-Authorization grammar): "Proxy-Authorization = credentials"
    pub fn message(self, field: &str) -> String {
        match self {
            Self::Empty => format!("{field} header is empty"),
            Self::SchemeCharacter(c) => {
                format!("Invalid character '{c}' in {field} auth-scheme")
            }
            Self::MissingCredentials => {
                format!("{field} header missing credentials after auth-scheme")
            }
            Self::CredentialsControlCharacter => {
                format!("{field} credentials contain control characters")
            }
            // The production's own sentence, which names the field it was read
            // from because four fields carry it.
            Self::Credentials(defect) => defect.message(field),
        }
    }
}

/// Every way a `credentials` field value fails § 11.4's production, as
/// [`AuthorizationDefect`]s; empty when it conforms.
///
/// Unlike a `WWW-Authenticate` challenge, this requires the credentials — see
/// the § 11.4 note in the body for why, which is that every concrete scheme
/// this serves mandates them even though the framework grammar does not.
///
/// **The scheme cannot be missing here either.** Same argument as
/// [`validate_challenge_syntax`]: the value is trimmed and checked for
/// emptiness, so what precedes the first `is_sp_or_htab` is non-empty and
/// `trim_ows` cannot empty it. That makes three helpers in this module that
/// carried the same unreachable sentence, all three written the same way, and
/// naming the failures is what surfaced all three.
///
/// **What follows the scheme is § 11.4's own alternative, and this function used
/// to stop before it.** It asked whether the credentials were non-empty and held
/// no control octet, and called that the framework's grammar; the framework's
/// grammar is `[ 1*SP ( token68 / #auth-param ) ]`, which § 11.3 writes
/// identically and [`validate_scheme_tail`] has always read for a challenge. So
/// `Authorization: Custom realm="x", , q="1"` drew nothing while the same value
/// in `WWW-Authenticate` drew a finding, and every scheme without a rule of its
/// own — `Negotiate`, `NTLM`, anything bespoke — had its credentials read no
/// further than "there is something there".
pub fn validate_authorization_syntax(value: &str) -> Vec<AuthorizationDefect<'_>> {
    let v = trim_ows(value);
    if v.is_empty() {
        return vec![AuthorizationDefect::Empty];
    }

    let mut parts = v.splitn(2, is_sp_or_htab);
    let scheme = parts
        .next()
        .expect("splitn always yields at least one element");
    let scheme = trim_ows(scheme);
    // cite(RFC 9110 § 11.1): "It uses a case-insensitive token to identify the authentication scheme"
    //
    // Recorded and not returned: the credentials after it are the other half
    // of the production, cut at the same `1*SP`, and a second repair.
    //
    // The requirement that credentials follow is the concrete schemes', so it
    // is not said of a scheme that is not a `token`: no scheme was named whose
    // document could require anything.
    let mut out = Vec::new();
    if let Some(invalid) = crate::helpers::token::find_invalid_token_char(scheme) {
        out.push(AuthorizationDefect::SchemeCharacter(invalid));
    }
    let scheme_is_a_token = out.is_empty();

    // §11.4's grammar makes the part after the scheme optional ([ 1*SP … ]), so a
    // bare scheme is framework-valid. This helper still requires something there
    // because every concrete scheme it serves — Basic (RFC 7617), Bearer (RFC 6750),
    // Digest (RFC 7616) — mandates credentials, so a scheme with nothing after it is
    // treated as malformed. The cite anchors the structure (scheme, then optional
    // credentials), not the requirement, which is scheme-derived and stricter than
    // the framework grammar.
    // cite(RFC 9110 § 11.4): "credentials = auth-scheme [ 1*SP ( token68 / #auth-param ) ]"
    if let Some(rest) = parts.next() {
        let rest = trim_ows(rest);
        if rest.is_empty() {
            if scheme_is_a_token {
                out.push(AuthorizationDefect::MissingCredentials);
            }
            return out;
        }
        // Read before the alternative is chosen, and it stays ahead of the
        // production's own reading for that reason: a control octet is refused
        // by `token68`, by `token` and by `qdtext` alike, so this is the one
        // verdict that does not depend on which alternative was written. Moving
        // it behind `validate_scheme_tail` would trade an id an operator has
        // configured for one that says the same thing about a narrower half.
        //
        // **Except HTAB, which is a control octet and not refused.** `#auth-param`
        // prints `OWS` beside every comma and `qdtext` names HTAB outright, so
        // `realm="x",<HTAB>nonce="n"` conforms. It is also the one control
        // octet a field value can carry, so counting it here meant this was
        // the only way to reach the entry, and every finding it gave was false.
        // cite(RFC 9110 § 5.6.3, label: OWS grammar): "OWS            = *( SP / HTAB )"
        if rest
            .chars()
            .any(|c| ((c as u32) < 0x20 && c != '\t') || c == '\x7f')
        {
            out.push(AuthorizationDefect::CredentialsControlCharacter);
            return out;
        }
        // `Side::Credentials`, and the reason is not that the ambiguity is
        // absent here. A single bare word after the scheme is derived by
        // `token68` and by an `auth-param` whose value was left off on either
        // side of the framework. What differs is what the reader was looking
        // for: a challenge exists to hand a client parameters, so a word where
        // `realm="x"` belongs is a plausible mistake, while a single `token68`
        // *is* what `Negotiate`, `NTLM` and `DPoP` write and nothing is missing
        // from it.
        //
        // `MemberEmptiness::ReadHere`, because nothing has looked: a challenge's
        // commas have been through `split_and_group_challenges` before the walk
        // sees them and these have been through nothing.
        //
        // The scheme was read above under this type's own variant, so the
        // shared reading's verdict on the same octets is left out rather than
        // reported twice.
        out.extend(
            validate_scheme_tail(v, Side::Credentials, MemberEmptiness::ReadHere)
                .into_iter()
                .filter(|defect| !matches!(defect, AuthDefect::SchemeCharacter(_)))
                .map(AuthorizationDefect::Credentials),
        );
    } else if scheme_is_a_token {
        out.push(AuthorizationDefect::MissingCredentials);
    }
    out
}

/// What `Basic` credentials fail to be.
///
/// The split follows the two layers RFC 7617 stacks: the `token68` is base64,
/// and what it decodes to is a `user-pass`. [`Empty`](Self::Empty) and
/// [`Base64`](Self::Base64) are the outer one, the other three the inner —
/// which is the distinction a reader needs, because a defect in the inner layer
/// says the sender encoded something well and chose it badly.
///
/// This one is `Clone` rather than `Copy`, alone among the defect enums here,
/// and [`Base64`](Self::Base64) is why: `base64::DecodeError` names the
/// offending symbol and its offset, which is worth carrying and is not `Copy`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BasicCredentialsDefect {
    /// No `token68` at all.
    Empty,
    /// Not base64. Carries the decoder's own account of where it stopped —
    /// rejecting a malformed encoding is RFC 4648's instruction rather than
    /// strictness for its own sake.
    Base64(base64::DecodeError),
    /// Decoded octets with no `:` in them. Without the separator there is no
    /// telling where the user-id stops, and `user-id` may itself be empty —
    /// which is a different thing from absent.
    MissingColon,
    /// A control octet in the user-id, carrying it.
    UserIdControlCharacter(u8),
    /// A control octet in the password, carrying it.
    PasswordControlCharacter(u8),
}

impl BasicCredentialsDefect {
    /// The finding. The `0x` spelling is deliberate for the two control-octet
    /// variants: the octet is by definition one that would not survive being
    /// printed into the sentence reporting it.
    pub fn message(self) -> String {
        match self {
            Self::Empty => "Basic credentials token is empty".to_string(),
            Self::Base64(e) => format!("Invalid base64 in Basic credentials: {}", e),
            Self::MissingColon => "Decoded Basic credentials missing ':' separator".to_string(),
            Self::UserIdControlCharacter(b) => {
                format!("User-id contains control character: 0x{:02x}", b)
            }
            Self::PasswordControlCharacter(b) => {
                format!("Password contains control character: 0x{:02x}", b)
            }
        }
    }
}

/// Whether a `Basic` `token68` is well-formed credentials, answered as a
/// [`BasicCredentialsDefect`].
///
/// Validation performed:
/// - Base64 decodes successfully
/// - Decoded octets contain at least one ':' separator
/// - User-id (octets before first ':') does not contain control characters
/// - Password (octets after first ':') does not contain control characters
///
/// **A successful decode here is never empty, and the guard that said otherwise
/// is gone.** Zero octets come out of zero base64 symbols; the value is trimmed
/// and rejected for emptiness above, so there is at least one symbol, and one
/// alone is `InvalidLength`. `"Decoded Basic credentials empty"` was a sentence
/// no input produced. If the decoder ever did return nothing for something, the
/// next line reports a `user-pass` with no `:` in it — which is what it would
/// be.
pub fn validate_basic_credentials(token68: &str) -> Result<(), BasicCredentialsDefect> {
    let s = trim_ows(token68);
    if s.is_empty() {
        return Err(BasicCredentialsDefect::Empty);
    }
    // cite(RFC 7617 § 2, label: basic-credentials base64): "and obtains the basic-credentials by encoding this octet sequence using Base64"
    // Erroring out on a malformed encoding is RFC 4648's own instruction, not
    // strictness for its own sake — and RFC 7617 does not state otherwise.
    // cite(RFC 4648 § 3.3, label: base64 rejects non-alphabet): "Implementations MUST reject the encoded data if it contains characters outside the base alphabet when interpreting base-encoded data, unless the specification referring to this document explicitly states otherwise."
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(BasicCredentialsDefect::Base64)?;
    // find first colon separator
    // cite(RFC 7617 § 2): "constructs the user-pass by concatenating the user-id, a single colon (":") character, and the password"
    let Some(pos) = decoded.iter().position(|b| *b == b':') else {
        return Err(BasicCredentialsDefect::MissingColon);
    };
    let (user, pass) = decoded.split_at(pos);
    // pass starts with ':' character; skip it
    let pass = &pass[1..];

    // cite(RFC 7617 § 2): "The user-id and password MUST NOT contain any control characters"
    let contains_ctl =
        |bytes: &[u8]| -> Option<u8> { bytes.iter().find(|&&b| b < 0x20 || b == 0x7f).copied() };

    if let Some(v) = contains_ctl(user) {
        return Err(BasicCredentialsDefect::UserIdControlCharacter(v));
    }
    if let Some(v) = contains_ctl(pass) {
        return Err(BasicCredentialsDefect::PasswordControlCharacter(v));
    }

    Ok(())
}

/// What a `Bearer` token fails to be.
///
/// All five are the one production, `b64token`, read in the order its ABNF
/// writes it: something, then the body's alphabet, then the padding.
/// [`Whitespace`](Self::Whitespace) is separated from
/// [`BadCharacter`](Self::BadCharacter) although a space is just another
/// character outside the set, because a token with a space in it is usually two
/// things where one was expected rather than one thing misspelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BearerTokenDefect {
    /// No token.
    Empty,
    /// Whitespace anywhere in the token.
    Whitespace,
    /// Padding and nothing before it. `b64token` is `1*(...)` and then its
    /// `*"="`, so the body cannot be the empty string.
    EmptyBody,
    /// An octet outside `b64token`'s body alphabet, carrying the character.
    BadCharacter(char),
    /// Something other than `=` at or after the first `=`. Padding is the only
    /// thing that may follow the body, so a `=` in the middle makes everything
    /// after it padding by position.
    BadPadding,
}

impl BearerTokenDefect {
    /// The finding. Each names `Bearer`, because a caller has one field's worth
    /// of context to add and this helper serves one scheme.
    pub fn message(self) -> String {
        match self {
            Self::Empty => "Bearer token is empty".to_string(),
            Self::Whitespace => "Bearer token contains whitespace".to_string(),
            Self::EmptyBody => "Bearer token has empty main part".to_string(),
            Self::BadCharacter(c) => format!("Invalid character '{}' in Bearer token", c),
            Self::BadPadding => "Bearer token padding contains invalid character".to_string(),
        }
    }
}

/// Validate Bearer token per token68-like rules: token must be non-empty, contain no
/// whitespace, the main body may contain only ALPHA / DIGIT / '-' / '.' / '_' / '~' / '+' / '/'
/// and any trailing padding must be '=' characters, answered as a
/// [`BearerTokenDefect`].
pub fn validate_bearer_token(token: &str) -> Result<(), BearerTokenDefect> {
    let s = trim_ows(token);
    if s.is_empty() {
        return Err(BearerTokenDefect::Empty);
    }

    // No whitespace anywhere
    if s.chars().any(|c| c.is_ascii_whitespace()) {
        return Err(BearerTokenDefect::Whitespace);
    }

    // Split at first '=' to identify padding (if any)
    let first_eq = s.find('=');
    let (main, padding) = match first_eq {
        Some(idx) => (&s[..idx], &s[idx..]),
        None => (s, ""),
    };

    if main.is_empty() {
        return Err(BearerTokenDefect::EmptyBody);
    }

    // cite(RFC 6750 § 2.1, label: bearer b64token grammar): "b64token    = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"=""
    let allowed_main =
        |c: char| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~' | '+' | '/');

    for c in main.chars() {
        if !allowed_main(c) {
            return Err(BearerTokenDefect::BadCharacter(c));
        }
    }

    for c in padding.chars() {
        if c != '=' {
            return Err(BearerTokenDefect::BadPadding);
        }
    }

    Ok(())
}

/// What one member of an `#auth-param` list fails to be.
///
/// Four variants and three of them belong to another subject: the list
/// construct's empty element, and the `token` an `auth-param` name has to be.
/// The fourth is `auth-param`'s own — that the `=` and the value after it are
/// not optional — and no subject holds it, because § 5.6.6's `parameter` is a
/// different production with `BWS` where this one has none.
///
/// The type exists so the rule reading these can name *which*; it used to
/// receive one rendered sentence and could only pass it on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthParamsDefect<'a> {
    /// A member contributing nothing to the list: a stray or trailing comma.
    Empty,
    /// A member whose name is empty — the `=` with nothing before it.
    NameEmpty,
    /// A character in the name that no `tchar` admits.
    NameCharacter(char),
    /// A member with no `=` in it at all. Carries the name, because the
    /// finding names the parameter that owes a value.
    ValueMissing(&'a str),
}

impl AuthParamsDefect<'_> {
    /// The finding, worded as every caller has always worded it.
    pub fn message(self) -> String {
        match self {
            Self::Empty => "empty auth-param".into(),
            Self::NameEmpty => "empty auth-param name".into(),
            Self::NameCharacter(c) => {
                format!("Invalid character '{}' in auth-param name", c)
            }
            Self::ValueMissing(name) => format!("auth-param '{}' missing value", name),
        }
    }
}

/// Parse an auth-param list (e.g., `username="Mufasa", realm="x", nonce=abc`) into a
/// HashMap of (name -> value) pairs. Values preserve quotes when present (e.g., `"x"`).
///
/// **A name written twice keeps the first value, and this used to keep the
/// last.** § 11.2 admits a parameter name once per challenge and says nothing
/// about what a recipient does with two, so the choice is the reader's — but
/// only one of the two is safe to make, because these callers are grading the
/// value rather than acting on it. Keeping the last means a sender can take a
/// finding away by *adding* a parameter: `Digest realm=foo` is a
/// `digest_challenge_quoting_invalid`, and `Digest realm=foo, realm="ok"` was
/// silent, because the well-formed second occurrence overwrote the malformed
/// first before any rule saw it. Keeping the first cannot do that — nothing a
/// sender appends changes what is already there — and it is the reading the
/// rest of this catalogue takes: `forwarded_header_valid` grades the first
/// occurrence and skips every later one, and the realm walk two functions up
/// says "the first realm and not the last" for the same reason.
///
/// The duplication itself is not this function's finding. It is
/// [`AuthDefect::ParameterDuplicated`], measured in
/// [`validate_scheme_tail`] where the challenge that scopes the count exists;
/// returning it here would collapse a whole challenge's worth of readings into
/// one id for a value every member of which is well formed.
///
/// **The defects are values and not sentences.** Rendering one is
/// [`AuthParamsDefect::message`] at the call site. Three of the four are
/// *nameable* by a caller reporting through the catalogue: the empty member is
/// the list's, and the two about the name are the `token`'s.
///
/// **A malformed member is set aside, and the rest are still read.** This
/// returned an `Err` at the first, and four rules call it: one reported the
/// `Err` and three treated it as "there is nothing here to reason about". So
/// `Digest realm="r", nonce=abc, =x` lost `digest_challenge_quoting_invalid` on
/// its `nonce` to a member that has nothing to do with it -- a refusal standing
/// in for a verdict about every other member. The map holds the members that
/// parse and the defects hold the ones that did not, in the order written.
///
/// The name is measured here rather than left to the caller, which is why
/// `digest_auth_valid`'s own name check answers nothing: a member whose name is
/// not a `token` never reaches the map.
// cite(RFC 9110 § 11.2): "auth-param     = token BWS "=" BWS ( token / quoted-string )"
// cite(RFC 9110 § 5.6.1.1): "In any production that uses the list construct, a sender MUST NOT generate empty list elements."
pub fn parse_auth_params(
    s: &str,
) -> (
    std::collections::HashMap<String, String>,
    Vec<AuthParamsDefect<'_>>,
) {
    let mut out = std::collections::HashMap::new();
    let mut defects = Vec::new();
    // split comma-separated params respecting quoted-strings
    for part in split_commas_respecting_quotes(s) {
        let p = part;
        if p.is_empty() {
            defects.push(AuthParamsDefect::Empty);
            continue;
        }
        let mut kv = p.splitn(2, '=');
        let Some(name) = kv.next().map(trim_ows).filter(|x| !x.is_empty()) else {
            defects.push(AuthParamsDefect::NameEmpty);
            continue;
        };
        let Some(val) = kv.next().map(trim_ows) else {
            defects.push(AuthParamsDefect::ValueMissing(name));
            continue;
        };
        // name must be a token
        if let Some(inv) = crate::helpers::token::find_invalid_token_char(name) {
            defects.push(AuthParamsDefect::NameCharacter(inv));
            continue;
        }
        out.entry(name.to_ascii_lowercase())
            .or_insert_with(|| val.to_string());
    }
    (out, defects)
}

/// Parse the hexadecimal nonce-count value (`nc` auth-param).
///
/// The specification requires exactly eight hex digits, so we enforce that here
/// and convert to a `u64` for easy comparison.  The returned error string is
/// suitable for inclusion in violation messages.
pub fn parse_nc_hex(s: &str) -> Result<u64, String> {
    let s = trim_ows(s);
    // RFC 7616 gives `nc` no ABNF at all. § 3.4 introduces it as "the hexadecimal
    // count" and never fixes its width; the sentence below is the only place in the
    // document that does. It sits in § 3.5, about Authentication-Info, but the same
    // section requires that field's nc to be the one from the client's request — so
    // it is one value with one width, and this is where the width is written down.
    // cite(RFC 7616 § 3.5): "For historical reasons, the nc value MUST be exactly 8 hexadecimal digits."
    if s.len() != 8 {
        return Err("nc must be exactly 8 hex digits".into());
    }
    u64::from_str_radix(s, 16).map_err(|e| format!("invalid hex nc: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The one defect a value carries, or `Ok` for none. These cases were
    /// each written for a value holding at most one defect, when the readings
    /// returned at the first; this keeps them saying so, and panics if a value
    /// turns out to hold a second -- which is the case the readings used to
    /// hide, and belongs in a test that says it.
    fn one<T: std::fmt::Debug>(defects: Vec<T>) -> Result<(), T> {
        let mut it = defects.into_iter();
        let first = it.next();
        let rest: Vec<T> = it.collect();
        assert!(
            rest.is_empty(),
            "a second defect beside {first:?}: {rest:?}"
        );
        first.map_or(Ok(()), Err)
    }

    /// The challenges, or the one list defect, in the shape the grouping
    /// answered with before it read past its first.
    /// The map, or the one member defect, in the shape the parse answered
    /// with before it read past its first.
    fn parsed(
        value: &str,
    ) -> Result<std::collections::HashMap<String, String>, AuthParamsDefect<'_>> {
        let (map, defects) = parse_auth_params(value);
        one(defects).map(|()| map)
    }

    /// A malformed member is set aside and the rest are still read: a
    /// `Digest` challenge's `nonce` is graded whatever sits beside it.
    #[test]
    fn a_malformed_member_does_not_withdraw_the_others() {
        let (map, defects) = parse_auth_params("realm=\"r\", =x, nonce=abc, b@d=1");
        assert_eq!(map.get("nonce").map(String::as_str), Some("abc"));
        assert_eq!(map.get("realm").map(String::as_str), Some("\"r\""));
        assert_eq!(
            defects,
            vec![
                AuthParamsDefect::NameEmpty,
                AuthParamsDefect::NameCharacter('@')
            ]
        );
    }

    fn grouped(value: &str) -> Result<Vec<String>, AuthDefect<'_>> {
        let (challenges, defects) = split_and_group_challenges(value);
        one(defects).map(|()| challenges)
    }
    use rstest::rstest;

    /// The trim and the split are `OWS`, so an `obs-text` octet is content:
    /// padding a scheme with one leaves it in the scheme, where the `token`
    /// alphabet refuses it, instead of trimming the value into validity.
    #[test]
    fn an_obs_text_octet_is_neither_padding_nor_a_separator() {
        let padded: String = std::iter::once('\u{a0}').chain("Basic x".chars()).collect();
        assert!(matches!(
            one(validate_authorization_syntax(&padded)),
            Err(AuthorizationDefect::SchemeCharacter('\u{a0}'))
        ));
        // The whitespace the grammar does print is still a separator.
        assert!(one(validate_authorization_syntax("Basic\tx")).is_ok());
    }

    /// The splitter itself, over the octets the callers disagreed about. The
    /// tail is `None` for a scheme alone and `Some("")` for a separator with
    /// nothing after it, and those are two different `credentials`: the first
    /// is legal, the second is not.
    #[rstest]
    #[case("Bearer abc", "Bearer", Some("abc"))]
    #[case("Bearer\tabc", "Bearer", Some("abc"))]
    #[case("  Bearer   abc  ", "Bearer", Some("abc"))]
    #[case("Bearer", "Bearer", None)]
    // `OWS` is outside the field value, so a trailing separator is not one:
    // these two are the same `credentials` and answer the same way.
    #[case("Bearer ", "Bearer", None)]
    #[case("Bearer\t", "Bearer", None)]
    // %xA0 and %x85 are `obs-text`: neither a separator nor padding, so each
    // stays in whichever half the sender put it in and is that production's
    // defect. A `char::is_whitespace` splitter cut here and trimmed here.
    #[case("Bearer abc\u{a0}", "Bearer", Some("abc\u{a0}"))]
    #[case("Bearer abc\u{85}", "Bearer", Some("abc\u{85}"))]
    #[case("\u{a0}Bearer abc", "\u{a0}Bearer", Some("abc"))]
    #[case("Bearer\u{a0}abc", "Bearer\u{a0}abc", None)]
    fn split_scheme_and_tail_cuts_at_the_separator_the_grammar_writes(
        #[case] value: &str,
        #[case] scheme: &str,
        #[case] tail: Option<&str>,
    ) {
        assert_eq!(split_scheme_and_tail(value), (scheme, tail));
    }

    /// The silence the split used to produce, at the reader that produced it.
    /// A trailing `obs-text` octet was trimmed away and the shortened value was
    /// a conforming `b64token`, so a value the sender wrote wrong reported
    /// nothing — which is worse than reporting it wrong, because nothing
    /// downstream can notice.
    #[test]
    fn a_trailing_obs_text_octet_is_part_of_the_token_and_not_padding() {
        let (scheme, tail) = split_scheme_and_tail("Bearer abcdef\u{a0}");
        assert_eq!(scheme, "Bearer");
        assert_eq!(
            validate_bearer_token(tail.expect("a separator was written")),
            Err(BearerTokenDefect::BadCharacter('\u{a0}'))
        );
        // The same value without the octet is the one that may be silent.
        assert!(validate_bearer_token("abcdef").is_ok());
    }

    #[test]
    fn basic_single_challenge() {
        let got = grouped("Basic realm=\"x\"").unwrap();
        assert_eq!(got, vec!["Basic realm=\"x\"".to_string()]);
    }

    /// A member holding only the octet %xA0 is not empty: § 5.6.1's empty
    /// element has nothing in it but OWS, and `str::trim` took the octet for
    /// whitespace.
    #[test]
    fn a_credentials_member_holding_an_obs_text_octet_is_not_empty() {
        let value: String = "Digest username=\"u\", \u{a0}".to_string();
        assert!(!matches!(
            one(validate_authorization_syntax(&value)),
            Err(AuthorizationDefect::Credentials(
                AuthDefect::ParameterMemberEmpty
            ))
        ));
        assert!(matches!(
            one(validate_authorization_syntax("Digest username=\"u\", ")),
            Err(AuthorizationDefect::Credentials(
                AuthDefect::ParameterMemberEmpty
            ))
        ));
    }

    #[test]
    fn validate_authorization_basic_ok() {
        assert!(one(validate_authorization_syntax(
            "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
        ))
        .is_ok());
    }

    #[test]
    fn parse_nc_hex_valid() {
        assert_eq!(parse_nc_hex("00000001").unwrap(), 1);
        assert_eq!(parse_nc_hex("0000000a").unwrap(), 10);
        assert_eq!(parse_nc_hex("ffffffff").unwrap(), 0xffffffff);
    }

    #[test]
    fn parse_nc_hex_errors() {
        assert!(parse_nc_hex("1").is_err());
        assert!(parse_nc_hex("0000000g").is_err());
        assert!(parse_nc_hex("00000").is_err());
    }

    #[test]
    fn validate_authorization_digest_missing_credentials() {
        assert!(one(validate_authorization_syntax("Digest")).is_err());
    }

    #[test]
    fn validate_authorization_bearer_ok() {
        assert!(one(validate_authorization_syntax("Bearer abc123")).is_ok());
    }

    #[test]
    fn validate_authorization_digest_ok() {
        assert!(one(validate_authorization_syntax(
            "Digest username=\"Mufasa\", realm=\"test\""
        ))
        .is_ok());
    }

    /// Both spellings of the same thing: a scheme with no second half, and a
    /// scheme whose second half is whitespace. The second reaches a different
    /// line of the function and used to carry a separately written copy of the
    /// same sentence.
    #[test]
    fn validate_authorization_missing_credentials() {
        assert_eq!(
            one(validate_authorization_syntax("Basic")),
            Err(AuthorizationDefect::MissingCredentials)
        );
        assert_eq!(
            one(validate_authorization_syntax("Basic ")),
            Err(AuthorizationDefect::MissingCredentials)
        );
    }

    #[test]
    fn validate_authorization_invalid_scheme_char() {
        assert_eq!(
            one(validate_authorization_syntax("B@sic xyz")),
            Err(AuthorizationDefect::SchemeCharacter('@'))
        );
    }

    #[test]
    fn validate_authorization_control_chars() {
        assert_eq!(
            one(validate_authorization_syntax("Bearer \u{0001}")),
            Err(AuthorizationDefect::CredentialsControlCharacter)
        );
    }

    /// HTAB is a control octet and `OWS`: beside an `#auth-param` comma and
    /// inside a `quoted-string` it conforms, and it is left to the production
    /// rather than counted among the octets both alternatives refuse.
    #[test]
    fn a_tab_where_the_production_admits_one_is_not_a_control_octet() {
        assert_eq!(
            one(validate_authorization_syntax(
                "Digest username=\"u\",\trealm=\"x\""
            )),
            Ok(())
        );
        assert_eq!(
            one(validate_authorization_syntax(
                "Digest username=\"u\"\t,\trealm=\"a\tb\""
            )),
            Ok(())
        );
    }

    /// An empty field value is empty, and a field value that is only
    /// whitespace is the same thing — § 5.5 does not count either as part of
    /// the value. Neither is a missing `auth-scheme`, which is a defect this
    /// function has no variant for because no input reaches it.
    #[test]
    fn validate_authorization_empty() {
        assert_eq!(
            one(validate_authorization_syntax("")),
            Err(AuthorizationDefect::Empty)
        );
        assert_eq!(
            one(validate_authorization_syntax("   ")),
            Err(AuthorizationDefect::Empty)
        );
    }

    #[test]
    fn multiple_members_grouped_into_challenge() {
        let got = grouped("Basic, realm=\"x\"").unwrap();
        assert_eq!(got, vec!["Basic, realm=\"x\"".to_string()]);
    }

    #[test]
    fn quoted_commas_are_respected() {
        let got = grouped("Basic realm=\"a,b\", more=1").unwrap();
        assert_eq!(got, vec!["Basic realm=\"a,b\", more=1".to_string()]);
    }

    /// Whitespace on either side of an `auth-param`'s `=` is `BWS`, on either
    /// side of the framework. It used to be held back behind the realm's
    /// spelling, so a token realm in one member hid the whitespace in another;
    /// they are two members and two repairs.
    #[test]
    fn whitespace_beside_an_auth_params_equals_is_bws() {
        for (value, side, member) in [
            ("Basic realm = \"x\"", Side::Challenge, "realm = \"x\""),
            (
                "Digest realm=\"x\", algorithm = SHA-256",
                Side::Challenge,
                "algorithm = SHA-256",
            ),
            (
                "Digest realm=\"x\", nonce\t=\"n\"",
                Side::Challenge,
                "nonce\t=\"n\"",
            ),
            (
                "Digest username= \"u\", realm=\"x\"",
                Side::Credentials,
                "username= \"u\"",
            ),
        ] {
            assert_eq!(
                one(validate_scheme_tail(value, side, MemberEmptiness::ReadHere)),
                Err(AuthDefect::ParameterBws(member)),
                "{value}"
            );
        }
        assert_eq!(
            validate_scheme_tail(
                "Custom realm=x, a = b",
                Side::Challenge,
                MemberEmptiness::ReadHere
            ),
            vec![
                AuthDefect::RealmUnquoted("x"),
                AuthDefect::ParameterBws("a = b")
            ]
        );
        assert_eq!(
            one(validate_scheme_tail(
                "Basic  realm=\"x\",\tcharset=\"UTF-8\"",
                Side::Challenge,
                MemberEmptiness::ReadHere
            )),
            Ok(())
        );
    }

    /// `BWS` before an `auth-param`'s `=` is whitespace inside a parameter, not
    /// the `1*SP` after a scheme: no challenge continues with `=`.
    #[test]
    fn a_parameter_with_whitespace_before_its_equals_continues_the_challenge() {
        for value in [
            "Digest realm=\"x\", algorithm = SHA-256",
            "Digest realm=\"x\", algorithm =SHA-256",
            "Digest realm=\"x\", algorithm\t=\tSHA-256",
        ] {
            let got = grouped(value).unwrap();
            assert_eq!(got, vec![value.to_string()], "{value}");
        }
        // A scheme and then a parameter is still two challenges.
        let got = grouped("Basic realm=\"a\", Newauth realm = \"b\"").unwrap();
        assert_eq!(got.len(), 2);
    }

    #[test]
    fn multiple_challenges() {
        let got = grouped("Basic realm=\"a\", NewScheme abc=").unwrap();
        assert_eq!(
            got,
            vec![
                "Basic realm=\"a\"".to_string(),
                "NewScheme abc=".to_string()
            ]
        );
    }

    #[test]
    fn empty_member_is_error() {
        let r = grouped(", Basic realm=\"x\"");
        assert_eq!(r.unwrap_err(), AuthDefect::EmptyMember);
    }

    #[test]
    fn parameter_before_scheme_is_error() {
        let r = grouped("error=\"x\"");
        assert_eq!(r.unwrap_err(), AuthDefect::SchemeMissing);
    }

    /// The leading space is `#challenge`'s own `OWS`, so this member is the one
    /// above with whitespace in front of it and draws the same message. It used
    /// to draw a different one, chosen by a character the list grammar puts
    /// outside the element.
    #[test]
    fn a_members_leading_ows_does_not_change_what_it_is() {
        for value in [" realm=\"x\"", "\trealm=\"x\"", "realm=\"x\"  "] {
            let r = grouped(value);
            assert!(
                r.as_ref().is_err_and(|e| *e == AuthDefect::SchemeMissing),
                "{value}: {r:?}"
            );
        }
    }

    #[test]
    fn consecutive_commas_report_error() {
        let r = grouped("Basic realm=\"x\", , error=\"y\"");
        assert_eq!(r.unwrap_err(), AuthDefect::EmptyMember);
    }

    /// § 11.2's count is scoped to a challenge, and § 11.4 gives `credentials`
    /// no such unit — one field carries one `credentials` and no list around
    /// it. RFC 7616 states nothing of its own about a Digest credential naming
    /// a parameter twice either, so a finding on the credentials side would be
    /// this reader's invention rather than a document's requirement.
    ///
    /// This is `Side`'s second decision, beside the bare word after a scheme,
    /// and it is asserted rather than left to the caller list: both sides reach
    /// the same walk, so a check written without the gate would report about an
    /// `Authorization` and nothing in the tree would say it should not.
    #[test]
    fn a_repeated_parameter_is_the_challenge_sides_alone() {
        let value = "Custom realm=\"a\", realm=\"b\"";
        assert_eq!(
            one(validate_scheme_tail(
                value,
                Side::Challenge,
                MemberEmptiness::AlreadyRefused
            )),
            Err(AuthDefect::ParameterDuplicated("realm"))
        );
        assert_eq!(
            one(validate_scheme_tail(
                value,
                Side::Credentials,
                MemberEmptiness::ReadHere
            )),
            Ok(())
        );
    }

    /// Two facts about one subject, and the walk names one of them.
    ///
    /// A value that is both — a realm written twice and written as a token —
    /// is answered by the duplication alone, because § 11.5's reading takes
    /// *the first* realm and can only do that by assuming there is one: naming
    /// the spelling of a value the recipient may not be using sends a sender to
    /// repair something that was never the subject.
    #[test]
    fn duplication_is_named_before_the_realms_spelling() {
        assert_eq!(
            one(validate_scheme_tail(
                "Basic realm=a, realm=b",
                Side::Challenge,
                MemberEmptiness::AlreadyRefused
            )),
            Err(AuthDefect::ParameterDuplicated("realm"))
        );
        // And with one realm the historical reason is what is left.
        assert_eq!(
            one(validate_scheme_tail(
                "Basic realm=a",
                Side::Challenge,
                MemberEmptiness::AlreadyRefused
            )),
            Err(AuthDefect::RealmUnquoted("a"))
        );
    }

    /// Every member answers for itself. The walk used to return on the first
    /// member that failed `auth-param`, so a duplicate after a malformed
    /// member was never counted, and a second malformed member was reported
    /// only once the first had been repaired.
    #[test]
    fn a_member_outside_the_production_does_not_hide_the_rest() {
        assert_eq!(
            validate_scheme_tail(
                "Basic realm=\"a\", bad@name=x, realm=\"b\"",
                Side::Challenge,
                MemberEmptiness::AlreadyRefused
            ),
            vec![
                AuthDefect::ParameterNameCharacter {
                    name: "bad@name",
                    character: '@'
                },
                AuthDefect::ParameterDuplicated("realm"),
            ]
        );
    }

    #[test]
    fn parse_auth_params_ok_and_lowercases_names() {
        let got = parsed("username=\"Mufasa\", realm=\"x\", nonce=abc").unwrap();
        assert_eq!(got.get("username").map(|s| s.as_str()), Some("\"Mufasa\""));
        assert_eq!(got.get("realm").map(|s| s.as_str()), Some("\"x\""));
        assert_eq!(got.get("nonce").map(|s| s.as_str()), Some("abc"));
    }

    /// The occurrence a reader meets first is the one the map keeps, so a
    /// sender cannot silence a finding about a malformed value by writing a
    /// well-formed one after it. This kept the last, and the shape it produced
    /// was the worst available: `Digest realm=foo` drew
    /// `digest_challenge_quoting_invalid` and `Digest realm=foo, realm="ok"`
    /// drew nothing about the realm at all.
    #[test]
    fn a_repeated_name_keeps_the_value_a_reader_meets_first() {
        let got = parsed(r#"realm=foo, realm="ok", nonce="n""#).unwrap();
        assert_eq!(got.get("realm").map(String::as_str), Some("foo"));
        // And the fold is the same one § 11.2 applies to the name.
        let got = parsed(r#"realm=foo, REALM="ok""#).unwrap();
        assert_eq!(got.get("realm").map(String::as_str), Some("foo"));
    }

    #[test]
    fn parse_auth_params_errors_on_missing_value_or_name() {
        assert!(parsed("username").is_err());
        assert!(parsed("=abc").is_err());
        assert!(parsed("").is_err());
    }

    #[test]
    fn parse_auth_params_invalid_name_char() {
        let r = parsed("user@name=abc");
        assert_eq!(r.unwrap_err(), AuthParamsDefect::NameCharacter('@'));
    }

    #[test]
    fn parse_auth_params_empty_member_is_error() {
        let r = parsed("a=b, , c=d");
        assert_eq!(r.unwrap_err(), AuthParamsDefect::Empty);
    }

    /// The four verdicts and the sentence each renders as, which is what every
    /// caller embedded when this returned a `String` — byte for byte, so the
    /// typing changed no message anywhere.
    #[test]
    fn each_auth_param_defect_renders_the_sentence_it_always_did() {
        for (input, defect, message) in [
            ("a=b, , c=d", AuthParamsDefect::Empty, "empty auth-param"),
            ("=abc", AuthParamsDefect::NameEmpty, "empty auth-param name"),
            (
                "user@name=abc",
                AuthParamsDefect::NameCharacter('@'),
                "Invalid character '@' in auth-param name",
            ),
            (
                "username",
                AuthParamsDefect::ValueMissing("username"),
                "auth-param 'username' missing value",
            ),
        ] {
            let got = parsed(input).unwrap_err();
            assert_eq!(got, defect, "{input}");
            assert_eq!(got.message(), message, "{input}");
        }
    }

    #[test]
    fn parse_auth_params_trailing_comma_is_error() {
        let r = parsed("a=b,");
        assert!(r.is_err());
    }

    /// The production's own answer, and the count is the part the caller uses:
    /// one padding octet leaves a value both alternatives of `challenge`
    /// derive, and more than one leaves a value only `token68` does.
    #[rstest]
    #[case("abc", Some(0))]
    #[case("abc=", Some(1))]
    #[case("abc==", Some(2))]
    #[case("YIIFxAYGKwYBBQUCoIIFuDCCBbSgh==", Some(2))]
    #[case("eyJhbGciOiJFUzI1NiJ9-_abc==", Some(2))]
    #[case("a.b~c+d/e", Some(0))]
    // A `=` that is not trailing padding closes nothing, so the value is
    // outside the production however the octets after it read.
    #[case("ab==cd", None)]
    #[case("realm=\"x\"", None)]
    // `1*(...)` before the padding: `=` alone derives no token68.
    #[case("=", None)]
    #[case("", None)]
    // The alphabet is `token68`'s, not `token`'s -- `!` and `@` are `tchar` and
    // neither is here.
    #[case("ab!cd", None)]
    #[case("ab@cd", None)]
    fn token68_padding_answers_the_production(
        #[case] value: &str,
        #[case] expected: Option<usize>,
    ) {
        assert_eq!(token68_padding(value), expected);
    }

    /// The shape a SPNEGO challenge is written in, which the reader used to
    /// hand to the parameter parser because it asked whether an `=` was present
    /// anywhere rather than whether the production put it there.
    #[rstest]
    #[case("Negotiate YIIFxAYGKwYBBQUCoIIFuDCCBbSgh==")]
    #[case("DPoP eyJhbGciOiJFUzI1NiJ9-_abc==")]
    #[case("NewScheme abc===")]
    fn a_padded_token68_is_the_credential_and_not_a_parameter(#[case] challenge: &str) {
        assert_eq!(one(validate_challenge_syntax(challenge)), Ok(()));
    }

    /// A member with no `=` and a member with an `=` and nothing after it are
    /// two mistakes, and one variant used to answer for both. The pair below is
    /// the assertion: `flag` left out the delimiter, `realm=` left out the
    /// value, and a sender told only "missing value" cannot tell which it made.
    #[test]
    fn a_member_without_its_delimiter_is_not_one_without_its_value() {
        assert_eq!(
            one(validate_challenge_syntax("Basic realm=\"x\", flag")),
            Err(AuthDefect::ParameterEqualsMissing("flag"))
        );
        assert_eq!(
            one(validate_challenge_syntax("NewSch realm=, other=1")),
            Err(AuthDefect::ParameterValueEmpty("realm"))
        );
    }

    /// Not a value any caller sends: `split_and_group_challenges` refuses an
    /// empty member before one is assembled. What is pinned is where the
    /// branch points now that it has no variant of its own — a challenge with
    /// nothing in it has no `auth-scheme`, which is a live id and not a dead
    /// arm.
    #[test]
    fn an_empty_challenge_has_no_auth_scheme() {
        assert_eq!(
            one(validate_challenge_syntax("")),
            Err(AuthDefect::SchemeMissing)
        );
    }

    /// The name is what the challenge *cannot* fail at. A member with leading
    /// `OWS` has already been trimmed by the time it gets here, so what this
    /// reads as the `auth-scheme` is `realm="x"` and the `=` is what it reports
    /// — never a missing scheme, which no input reaches.
    #[test]
    fn validate_missing_scheme_error() {
        assert_eq!(
            one(validate_challenge_syntax(" realm=\"x\"")),
            Err(AuthDefect::SchemeCharacter('='))
        );
    }

    #[test]
    fn validate_invalid_scheme_char() {
        assert_eq!(
            one(validate_challenge_syntax("B@sic realm=\"x\"")),
            Err(AuthDefect::SchemeCharacter('@'))
        );
    }

    #[test]
    fn validate_scheme_only_ok() {
        let r = one(validate_challenge_syntax("Basic"));
        assert!(r.is_ok());
    }

    #[test]
    fn suspicious_single_token_after_scheme_reports_error() {
        assert_eq!(
            one(validate_challenge_syntax("NewSch abcd")),
            Err(AuthDefect::SuspiciousSingleToken("abcd"))
        );
    }

    #[test]
    fn token68_with_control_character_reports_error() {
        assert_eq!(
            one(validate_challenge_syntax("NewSch \u{0001}")),
            Err(AuthDefect::Token68ControlCharacter)
        );
    }

    #[test]
    fn first_part_invalid_and_after_eq_no_quotes_permitted_as_token68() {
        let r = one(validate_challenge_syntax("NewSch bad@=abc"));
        assert!(r.is_ok());
    }

    // Tests for validate_bearer_token helper
    #[test]
    fn validate_bearer_token_ok_and_padding() {
        assert!(validate_bearer_token("abc123").is_ok());
        assert!(validate_bearer_token("abc+").is_ok());
        assert!(validate_bearer_token("abc==").is_ok());
    }

    #[test]
    fn validate_bearer_token_rejects_whitespace_and_invalid_chars() {
        assert_eq!(
            validate_bearer_token("a b"),
            Err(BearerTokenDefect::Whitespace)
        );
        assert_eq!(validate_bearer_token(""), Err(BearerTokenDefect::Empty));
        assert_eq!(
            validate_bearer_token("a@b"),
            Err(BearerTokenDefect::BadCharacter('@'))
        );
    }

    /// The four values here fail two different ways, which is what `is_err()`
    /// could not say. Everything from the first `=` is padding *by position*,
    /// so `ab=c` has well-formed body `ab` and padding `=c`; `=abc` has no body
    /// at all, and the padding it does have is never reached.
    #[test]
    fn validate_bearer_token_rejects_eq_in_middle_or_nonpad() {
        assert_eq!(
            validate_bearer_token("ab=c"),
            Err(BearerTokenDefect::BadPadding)
        );
        assert_eq!(
            validate_bearer_token("ab=c=="),
            Err(BearerTokenDefect::BadPadding)
        );
        assert_eq!(
            validate_bearer_token("=abc"),
            Err(BearerTokenDefect::EmptyBody)
        );
        assert_eq!(
            validate_bearer_token("abc=a"),
            Err(BearerTokenDefect::BadPadding)
        );
    }

    #[test]
    fn scheme_with_trailing_eq_on_basic_reports_the_empty_value() {
        assert_eq!(
            one(validate_challenge_syntax("Basic realm=")),
            Err(AuthDefect::ParameterValueEmpty("realm"))
        );
    }

    #[test]
    fn scheme_with_trailing_eq_on_non_basic_is_ok() {
        let r = one(validate_challenge_syntax("NewSch realm="));
        assert!(r.is_ok());
    }

    /// Also not a value any caller sends — the assembler joins members with
    /// `", "` and a non-empty member, so no assembled challenge ends in a
    /// separator. This used to report the empty member as a parameter whose
    /// name is empty, which is another defect's id; the walk is told its caller
    /// refused empty members and takes it at its word, and the caller that
    /// assembles challenges reports this one under the list's own entry.
    #[test]
    fn an_empty_auth_param_is_the_lists_to_report() {
        assert_eq!(
            one(validate_challenge_syntax("Basic realm=\"x\", ")),
            Ok(())
        );
        assert_eq!(grouped("Basic realm=\"x\", "), Err(AuthDefect::EmptyMember));
    }

    #[test]
    fn empty_param_name_is_error() {
        assert_eq!(
            one(validate_challenge_syntax("Basic =\"x\"")),
            Err(AuthDefect::EmptyParameterName("=\"x\""))
        );
    }

    #[test]
    fn invalid_character_in_param_name_is_error() {
        assert_eq!(
            one(validate_challenge_syntax("Basic re@alm=1, x=1")),
            Err(AuthDefect::ParameterNameCharacter {
                name: "re@alm",
                character: '@'
            })
        );
    }

    #[test]
    fn validate_basic_credentials_ok() {
        // 'Aladdin:open sesame' -> base64
        assert!(validate_basic_credentials("QWxhZGRpbjpvcGVuIHNlc2FtZQ==").is_ok());
    }

    #[test]
    fn validate_basic_credentials_missing_colon() {
        // 'abc' base64
        assert_eq!(
            validate_basic_credentials("YWJj"),
            Err(BasicCredentialsDefect::MissingColon)
        );
    }

    /// The two layers, one after the other: `not-base64!!` never becomes a
    /// `user-pass` to have anything wrong with, and the decoder says where it
    /// stopped. An empty encoding decodes fine and is the other thing.
    #[test]
    fn validate_basic_credentials_invalid_base64() {
        assert_eq!(
            validate_basic_credentials("not-base64!!"),
            Err(BasicCredentialsDefect::Base64(
                base64::DecodeError::InvalidByte(3, b'-')
            ))
        );
        assert_eq!(
            validate_basic_credentials("===="),
            Err(BasicCredentialsDefect::Base64(
                base64::DecodeError::InvalidByte(0, b'=')
            ))
        );
    }

    #[test]
    fn validate_basic_credentials_ctl_in_password() {
        // user:pass where pass contains 0x01
        let creds = b"user:\x01pass";
        let enc = base64::engine::general_purpose::STANDARD.encode(creds);
        assert_eq!(
            validate_basic_credentials(&enc),
            Err(BasicCredentialsDefect::PasswordControlCharacter(0x01))
        );
    }

    #[test]
    fn validate_basic_credentials_ctl_in_user() {
        // user contains 0x01
        let creds = b"us\x01er:pass";
        let enc = base64::engine::general_purpose::STANDARD.encode(creds);
        assert_eq!(
            validate_basic_credentials(&enc),
            Err(BasicCredentialsDefect::UserIdControlCharacter(0x01))
        );
    }

    #[test]
    fn validate_basic_credentials_empty_token() {
        assert_eq!(
            validate_basic_credentials(""),
            Err(BasicCredentialsDefect::Empty)
        );
    }
    #[test]
    fn validate_basic_credentials_empty_user_allowed() {
        // ':pass' should be allowed (empty user-id) as long as no control chars
        let creds = b":pass";
        let enc = base64::engine::general_purpose::STANDARD.encode(creds);
        assert!(validate_basic_credentials(&enc).is_ok());
    }

    /// The finding names the parameter *and* the defect, which is the pair a
    /// `String` could only carry pre-spliced. `NotQuoted` is the variant: the
    /// value opens with a DQUOTE and nothing closes it, so there is no interior
    /// to have a defect in.
    #[test]
    fn invalid_quoted_string_in_param_reports_error() {
        let r = one(validate_challenge_syntax("Basic realm=\"unterminated"));
        assert_eq!(
            r,
            Err(AuthDefect::ParameterQuotedValue {
                name: "realm",
                value: "\"unterminated",
                defect: crate::helpers::quoted_string::QuotedStringDefect::NotQuoted,
            })
        );
        assert!(r
            .unwrap_err()
            .message("WWW-Authenticate")
            .starts_with("Invalid quoted-string in WWW-Authenticate auth-param 'realm': "));
    }

    #[test]
    fn quoted_string_escaped_final_quote_reports_unterminated() {
        // Build the string programmatically to ensure exact control of contents:
        // Resulting string contains the characters: '"' 'a' 'b' 'c' '\' '"' i.e. "abc\"
        let mut s = String::new();
        s.push('"');
        s.push_str("abc");
        s.push('\\');
        s.push('"');
        let r = crate::helpers::quoted_string::validate_quoted_string(&s);
        // `\"` is a valid quoted-pair, so what is missing is the delimiter: the
        // value is an unterminated string, not one ending in a dangling escape.
        assert!(r.unwrap_err().contains("not properly quoted"));
    }

    /// Two `Invalid character` sentences that a `String` made
    /// indistinguishable: the octet is read under `auth-param`'s name in one
    /// and under its value in the other, and the pair below is a single header
    /// value away from each other. Which is also why the bad name needs the
    /// comma — a lone `re@alm=xy` never reaches the parameter loop, the
    /// token68 heuristic above it takes an unquoted value behind a non-`token`
    /// name as evidence that the whole thing is a `token68`.
    #[test]
    fn invalid_character_in_param_value_is_error() {
        assert_eq!(
            one(validate_challenge_syntax("Basic realm=x@y")),
            Err(AuthDefect::ParameterValueCharacter {
                name: "realm",
                character: '@'
            })
        );
        assert_eq!(
            one(validate_challenge_syntax("Basic re@alm=xy, x=1")),
            Err(AuthDefect::ParameterNameCharacter {
                name: "re@alm",
                character: '@'
            })
        );
        assert_eq!(one(validate_challenge_syntax("Basic re@alm=xy")), Ok(()));
    }

    #[test]
    fn token68_with_allowed_chars_ok() {
        let r = one(validate_challenge_syntax("NewSch abc+"));
        assert!(r.is_ok());
    }
}
