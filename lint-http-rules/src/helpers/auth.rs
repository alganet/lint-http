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

/// Split a WWW-Authenticate header value into "assembled" challenges.
///
/// This function splits top-level comma-separated members (respecting quoted-strings)
/// and groups members into challenges: a member that begins with an auth-scheme
/// (token followed by whitespace or end-of-member) starts a new challenge; subsequent
/// members without a leading scheme are treated as continuation parameters for
/// the current challenge.
///
/// Returns `Ok(Vec<String>)` on success or the [`AuthDefect`] naming a
/// parsing problem: an empty member, or a parameter with no challenge before
/// it. There was a third — *missing scheme on a member that starts with
/// whitespace* — and it was the same problem read off a character the list
/// grammar puts outside the element.
///
/// The two it can answer with are the list's rather than one challenge's, and
/// they are variants of the same type as the rest because a caller reports them
/// the same way: this function and [`validate_challenge_syntax`] are two halves
/// of reading one field value.
pub fn split_and_group_challenges(s: &str) -> Result<Vec<String>, AuthDefect<'_>> {
    let members: Vec<&str> = split_commas_respecting_quotes(s);
    let mut challenges: Vec<String> = Vec::new();

    for m in members {
        // The `OWS` the `#rule` prints around its commas is the splitter's to
        // remove, and it removes exactly that — the `str::trim` this replaced
        // also took %xA0 and %x85 off a member's ends, which are `obs-text` and
        // are two of the octets the `auth-scheme` check below exists to name.
        let mm = m;
        if mm.is_empty() {
            return Err(AuthDefect::EmptyMember);
        }

        let is_new = {
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
            return Err(AuthDefect::SchemeMissing);
        }
    }

    Ok(challenges)
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
    /// belongs to.
    EmptyParameterName,
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
    /// A non-`token` octet in an `auth-param` name, carrying the character.
    ParameterNameCharacter(char),
    /// A non-`token` octet in an unquoted `auth-param` value, carrying the
    /// character.
    ParameterValueCharacter(char),
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
            Self::EmptyParameterName => format!("{field} auth-param name is empty"),
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
            Self::ParameterNameCharacter(c) => {
                format!("Invalid character '{c}' in {field} auth-param name")
            }
            Self::ParameterValueCharacter(c) => {
                format!("Invalid character '{c}' in {field} auth-param value")
            }
            Self::ParameterQuotedValue {
                name,
                value,
                defect,
            } => format!(
                "Invalid quoted-string in {field} auth-param '{}': {}",
                name,
                defect.message(value)
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

/// Whether one assembled `WWW-Authenticate` challenge is syntactically
/// acceptable, answered as a [`AuthDefect`].
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
pub fn validate_challenge_syntax(challenge: &str) -> Result<(), AuthDefect<'_>> {
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
        return Err(AuthDefect::SchemeMissing);
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
) -> Result<(), AuthDefect<'_>> {
    // The three `token68` readings below share this: the alternative's alphabet
    // has no control octet in it, whichever way the value reached the branch.
    let has_control = |s: &str| s.chars().any(|c| (c as u32) < 0x20 || c == '\x7f');

    // scheme is first token before whitespace
    // cite(RFC 9110 § 11.3): "challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]"
    let mut parts = value.splitn(2, is_sp_or_htab);
    let scheme = parts
        .next()
        .expect("splitn always yields at least one element");
    let scheme = trim_ows(scheme);
    if let Some(invalid) = crate::helpers::token::find_invalid_token_char(scheme) {
        return Err(AuthDefect::SchemeCharacter(invalid));
    }

    if let Some(rest) = parts.next() {
        let rest = trim_ows(rest);
        if rest.is_empty() {
            return Ok(());
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
            return Ok(());
        }

        if !rest.contains('=') {
            if has_control(rest) {
                return Err(AuthDefect::Token68ControlCharacter);
            }
            if side == Side::Challenge
                && !rest
                    .chars()
                    .any(|ch| matches!(ch, '+' | '/' | '=' | '.' | '-' | '_'))
            {
                return Err(AuthDefect::SuspiciousSingleToken(rest));
            }
            return Ok(());
        }

        // rest contains '='; decide heuristics
        let first_part = trim_ows(rest.split('=').next().unwrap_or(""));
        let after_eq = trim_ows(rest.split_once('=').map(|x| x.1).unwrap_or(""));
        let first_invalid = crate::helpers::token::find_invalid_token_char(first_part).is_some();
        if !rest.contains(',') {
            if first_invalid && !after_eq.starts_with('"') {
                if has_control(rest) {
                    return Err(AuthDefect::Token68ControlCharacter);
                }
                return Ok(());
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
                        return Err(AuthDefect::Token68ControlCharacter);
                    }
                    return Ok(());
                }

                return Err(AuthDefect::ParameterValueEmpty(first_part));
            }
        }

        // Parse auth-params. The `OWS` around the `#auth-param` commas is the
        // splitter's; the `str::trim` this replaced also took the two `obs-text`
        // octets that look like whitespace, and no `token` admits either.
        // Whether an empty member is this walk's to report is the caller's
        // answer, and both answers are true of one of them: the challenge side's
        // commas have been through `split_and_group_challenges`, the credentials
        // side's have been through nothing.
        // cite(RFC 9110 § 5.6.1.1): "In any production that uses the list construct, a sender MUST NOT generate empty list elements."
        for param in split_commas_respecting_quotes(rest) {
            if members == MemberEmptiness::ReadHere && param.trim().is_empty() {
                return Err(AuthDefect::ParameterMemberEmpty);
            }
            let mut kv = param.splitn(2, '=');
            let name = kv
                .next()
                .expect("splitn always yields at least one element");
            let name = trim_ows(name);
            let val = kv.next();
            if name.is_empty() {
                return Err(AuthDefect::EmptyParameterName);
            }
            // The `=` and the value after it are two things a sender leaves out,
            // and one variant used to answer for both. A member with no `=` in
            // it derives from `auth-param` not at all; a member with an `=` and
            // nothing after it broke the floor of the two alternatives.
            let Some(val) = val else {
                return Err(AuthDefect::ParameterEqualsMissing(name));
            };
            if let Some(inv) = crate::helpers::token::find_invalid_token_char(name) {
                return Err(AuthDefect::ParameterNameCharacter(inv));
            }
            let v = trim_ows(val);
            if v.is_empty() {
                return Err(AuthDefect::ParameterValueEmpty(name));
            }
            if v.starts_with('"') {
                if let Err(defect) = crate::helpers::quoted_string::check_quoted_string(v) {
                    return Err(AuthDefect::ParameterQuotedValue {
                        name,
                        value: v,
                        defect,
                    });
                }
            } else if let Some(inv) = crate::helpers::token::find_invalid_token_char(v) {
                return Err(AuthDefect::ParameterValueCharacter(inv));
            }
        }
    }

    Ok(())
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
    /// A control octet in the credentials, read before the alternative is
    /// chosen. Both alternatives refuse it — `token68`'s alphabet holds no
    /// control octet and neither does a `token` or the `qdtext` of a
    /// `quoted-string` — so this is the one verdict about the value that does
    /// not need to know which of the two was written.
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

/// Whether a `credentials` field value is § 11.4's production, answered as an
/// [`AuthorizationDefect`].
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
pub fn validate_authorization_syntax(value: &str) -> Result<(), AuthorizationDefect<'_>> {
    let v = trim_ows(value);
    if v.is_empty() {
        return Err(AuthorizationDefect::Empty);
    }

    let mut parts = v.splitn(2, is_sp_or_htab);
    let scheme = parts
        .next()
        .expect("splitn always yields at least one element");
    let scheme = trim_ows(scheme);
    // cite(RFC 9110 § 11.1): "It uses a case-insensitive token to identify the authentication scheme"
    if let Some(invalid) = crate::helpers::token::find_invalid_token_char(scheme) {
        return Err(AuthorizationDefect::SchemeCharacter(invalid));
    }

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
            return Err(AuthorizationDefect::MissingCredentials);
        }
        // Read before the alternative is chosen, and it stays ahead of the
        // production's own reading for that reason: a control octet is refused
        // by `token68`, by `token` and by `qdtext` alike, so this is the one
        // verdict that does not depend on which alternative was written. Moving
        // it behind `validate_scheme_tail` would trade an id an operator has
        // configured for one that says the same thing about a narrower half.
        if rest.chars().any(|c| (c as u32) < 0x20 || c == '\x7f') {
            return Err(AuthorizationDefect::CredentialsControlCharacter);
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
        if let Err(defect) = validate_scheme_tail(v, Side::Credentials, MemberEmptiness::ReadHere) {
            return Err(AuthorizationDefect::Credentials(defect));
        }
        Ok(())
    } else {
        Err(AuthorizationDefect::MissingCredentials)
    }
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
/// **The `Err` is the defect and not a sentence.** Rendering it is
/// [`AuthParamsDefect::message`] at the call site — one method, and the string
/// is byte-identical to what this returned before. What the change buys is that
/// three of the four defects are *nameable* by a caller reporting through the
/// catalogue: the empty member is the list's, and the two about the name are
/// the `token`'s.
///
/// Four rules call this and one of them reports. The other three treat a
/// failure as "there is nothing here to reason about" and move on, which is
/// what makes the caller count an upper bound rather than a work list.
///
/// The name is measured here rather than left to the caller, which is why
/// `digest_auth_valid`'s own name check answers nothing: this returns first.
// cite(RFC 9110 § 11.2): "auth-param     = token BWS "=" BWS ( token / quoted-string )"
// cite(RFC 9110 § 5.6.1.1): "In any production that uses the list construct, a sender MUST NOT generate empty list elements."
pub fn parse_auth_params(
    s: &str,
) -> Result<std::collections::HashMap<String, String>, AuthParamsDefect<'_>> {
    let mut out = std::collections::HashMap::new();
    // split comma-separated params respecting quoted-strings
    for part in split_commas_respecting_quotes(s) {
        let p = part;
        if p.is_empty() {
            return Err(AuthParamsDefect::Empty);
        }
        let mut kv = p.splitn(2, '=');
        let name = kv
            .next()
            .map(trim_ows)
            .filter(|x| !x.is_empty())
            .ok_or(AuthParamsDefect::NameEmpty)?;
        let val = kv
            .next()
            .map(trim_ows)
            .ok_or(AuthParamsDefect::ValueMissing(name))?;
        // name must be a token
        if let Some(inv) = crate::helpers::token::find_invalid_token_char(name) {
            return Err(AuthParamsDefect::NameCharacter(inv));
        }
        out.insert(name.to_ascii_lowercase(), val.to_string());
    }
    Ok(out)
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
    use rstest::rstest;

    /// The trim and the split are `OWS`, so an `obs-text` octet is content:
    /// padding a scheme with one leaves it in the scheme, where the `token`
    /// alphabet refuses it, instead of trimming the value into validity.
    #[test]
    fn an_obs_text_octet_is_neither_padding_nor_a_separator() {
        let padded: String = std::iter::once('\u{a0}').chain("Basic x".chars()).collect();
        assert!(matches!(
            validate_authorization_syntax(&padded),
            Err(AuthorizationDefect::SchemeCharacter('\u{a0}'))
        ));
        // The whitespace the grammar does print is still a separator.
        assert!(validate_authorization_syntax("Basic\tx").is_ok());
    }

    #[test]
    fn basic_single_challenge() {
        let got = split_and_group_challenges("Basic realm=\"x\"").unwrap();
        assert_eq!(got, vec!["Basic realm=\"x\"".to_string()]);
    }

    #[test]
    fn validate_authorization_basic_ok() {
        assert!(validate_authorization_syntax("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==").is_ok());
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
        assert!(validate_authorization_syntax("Digest").is_err());
    }

    #[test]
    fn validate_authorization_bearer_ok() {
        assert!(validate_authorization_syntax("Bearer abc123").is_ok());
    }

    #[test]
    fn validate_authorization_digest_ok() {
        assert!(
            validate_authorization_syntax("Digest username=\"Mufasa\", realm=\"test\"").is_ok()
        );
    }

    /// Both spellings of the same thing: a scheme with no second half, and a
    /// scheme whose second half is whitespace. The second reaches a different
    /// line of the function and used to carry a separately written copy of the
    /// same sentence.
    #[test]
    fn validate_authorization_missing_credentials() {
        assert_eq!(
            validate_authorization_syntax("Basic"),
            Err(AuthorizationDefect::MissingCredentials)
        );
        assert_eq!(
            validate_authorization_syntax("Basic "),
            Err(AuthorizationDefect::MissingCredentials)
        );
    }

    #[test]
    fn validate_authorization_invalid_scheme_char() {
        assert_eq!(
            validate_authorization_syntax("B@sic xyz"),
            Err(AuthorizationDefect::SchemeCharacter('@'))
        );
    }

    #[test]
    fn validate_authorization_control_chars() {
        assert_eq!(
            validate_authorization_syntax("Bearer \u{0001}"),
            Err(AuthorizationDefect::CredentialsControlCharacter)
        );
    }

    /// An empty field value is empty, and a field value that is only
    /// whitespace is the same thing — § 5.5 does not count either as part of
    /// the value. Neither is a missing `auth-scheme`, which is a defect this
    /// function has no variant for because no input reaches it.
    #[test]
    fn validate_authorization_empty() {
        assert_eq!(
            validate_authorization_syntax(""),
            Err(AuthorizationDefect::Empty)
        );
        assert_eq!(
            validate_authorization_syntax("   "),
            Err(AuthorizationDefect::Empty)
        );
    }

    #[test]
    fn multiple_members_grouped_into_challenge() {
        let got = split_and_group_challenges("Basic, realm=\"x\"").unwrap();
        assert_eq!(got, vec!["Basic, realm=\"x\"".to_string()]);
    }

    #[test]
    fn quoted_commas_are_respected() {
        let got = split_and_group_challenges("Basic realm=\"a,b\", more=1").unwrap();
        assert_eq!(got, vec!["Basic realm=\"a,b\", more=1".to_string()]);
    }

    #[test]
    fn multiple_challenges() {
        let got = split_and_group_challenges("Basic realm=\"a\", NewScheme abc=").unwrap();
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
        let r = split_and_group_challenges(", Basic realm=\"x\"");
        assert_eq!(r.unwrap_err(), AuthDefect::EmptyMember);
    }

    #[test]
    fn parameter_before_scheme_is_error() {
        let r = split_and_group_challenges("error=\"x\"");
        assert_eq!(r.unwrap_err(), AuthDefect::SchemeMissing);
    }

    /// The leading space is `#challenge`'s own `OWS`, so this member is the one
    /// above with whitespace in front of it and draws the same message. It used
    /// to draw a different one, chosen by a character the list grammar puts
    /// outside the element.
    #[test]
    fn a_members_leading_ows_does_not_change_what_it_is() {
        for value in [" realm=\"x\"", "\trealm=\"x\"", "realm=\"x\"  "] {
            let r = split_and_group_challenges(value);
            assert!(
                r.as_ref().is_err_and(|e| *e == AuthDefect::SchemeMissing),
                "{value}: {r:?}"
            );
        }
    }

    #[test]
    fn consecutive_commas_report_error() {
        let r = split_and_group_challenges("Basic realm=\"x\", , error=\"y\"");
        assert_eq!(r.unwrap_err(), AuthDefect::EmptyMember);
    }

    #[test]
    fn parse_auth_params_ok_and_lowercases_names() {
        let got = parse_auth_params("username=\"Mufasa\", realm=\"x\", nonce=abc").unwrap();
        assert_eq!(got.get("username").map(|s| s.as_str()), Some("\"Mufasa\""));
        assert_eq!(got.get("realm").map(|s| s.as_str()), Some("\"x\""));
        assert_eq!(got.get("nonce").map(|s| s.as_str()), Some("abc"));
    }

    #[test]
    fn parse_auth_params_errors_on_missing_value_or_name() {
        assert!(parse_auth_params("username").is_err());
        assert!(parse_auth_params("=abc").is_err());
        assert!(parse_auth_params("").is_err());
    }

    #[test]
    fn parse_auth_params_invalid_name_char() {
        let r = parse_auth_params("user@name=abc");
        assert_eq!(r.unwrap_err(), AuthParamsDefect::NameCharacter('@'));
    }

    #[test]
    fn parse_auth_params_empty_member_is_error() {
        let r = parse_auth_params("a=b, , c=d");
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
            let got = parse_auth_params(input).unwrap_err();
            assert_eq!(got, defect, "{input}");
            assert_eq!(got.message(), message, "{input}");
        }
    }

    #[test]
    fn parse_auth_params_trailing_comma_is_error() {
        let r = parse_auth_params("a=b,");
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
        assert_eq!(validate_challenge_syntax(challenge), Ok(()));
    }

    /// A member with no `=` and a member with an `=` and nothing after it are
    /// two mistakes, and one variant used to answer for both. The pair below is
    /// the assertion: `flag` left out the delimiter, `realm=` left out the
    /// value, and a sender told only "missing value" cannot tell which it made.
    #[test]
    fn a_member_without_its_delimiter_is_not_one_without_its_value() {
        assert_eq!(
            validate_challenge_syntax("Basic realm=\"x\", flag"),
            Err(AuthDefect::ParameterEqualsMissing("flag"))
        );
        assert_eq!(
            validate_challenge_syntax("NewSch realm=, other=1"),
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
            validate_challenge_syntax(""),
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
            validate_challenge_syntax(" realm=\"x\""),
            Err(AuthDefect::SchemeCharacter('='))
        );
    }

    #[test]
    fn validate_invalid_scheme_char() {
        assert_eq!(
            validate_challenge_syntax("B@sic realm=\"x\""),
            Err(AuthDefect::SchemeCharacter('@'))
        );
    }

    #[test]
    fn validate_scheme_only_ok() {
        let r = validate_challenge_syntax("Basic");
        assert!(r.is_ok());
    }

    #[test]
    fn suspicious_single_token_after_scheme_reports_error() {
        assert_eq!(
            validate_challenge_syntax("NewSch abcd"),
            Err(AuthDefect::SuspiciousSingleToken("abcd"))
        );
    }

    #[test]
    fn token68_with_control_character_reports_error() {
        assert_eq!(
            validate_challenge_syntax("NewSch \u{0001}"),
            Err(AuthDefect::Token68ControlCharacter)
        );
    }

    #[test]
    fn first_part_invalid_and_after_eq_no_quotes_permitted_as_token68() {
        let r = validate_challenge_syntax("NewSch bad@=abc");
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
            validate_challenge_syntax("Basic realm="),
            Err(AuthDefect::ParameterValueEmpty("realm"))
        );
    }

    #[test]
    fn scheme_with_trailing_eq_on_non_basic_is_ok() {
        let r = validate_challenge_syntax("NewSch realm=");
        assert!(r.is_ok());
    }

    /// Also not a value any caller sends — the assembler joins members with
    /// `", "` and a non-empty member, so no assembled challenge ends in a
    /// separator. An empty `#auth-param` member is a parameter whose name is
    /// empty, and that is what it reports.
    #[test]
    fn an_empty_auth_param_is_a_parameter_with_no_name() {
        assert_eq!(
            validate_challenge_syntax("Basic realm=\"x\", "),
            Err(AuthDefect::EmptyParameterName)
        );
    }

    #[test]
    fn empty_param_name_is_error() {
        assert_eq!(
            validate_challenge_syntax("Basic =\"x\""),
            Err(AuthDefect::EmptyParameterName)
        );
    }

    #[test]
    fn invalid_character_in_param_name_is_error() {
        assert_eq!(
            validate_challenge_syntax("Basic re@alm=1, x=1"),
            Err(AuthDefect::ParameterNameCharacter('@'))
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
        let r = validate_challenge_syntax("Basic realm=\"unterminated");
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
            validate_challenge_syntax("Basic realm=x@y"),
            Err(AuthDefect::ParameterValueCharacter('@'))
        );
        assert_eq!(
            validate_challenge_syntax("Basic re@alm=xy, x=1"),
            Err(AuthDefect::ParameterNameCharacter('@'))
        );
        assert_eq!(validate_challenge_syntax("Basic re@alm=xy"), Ok(()));
    }

    #[test]
    fn token68_with_allowed_chars_ok() {
        let r = validate_challenge_syntax("NewSch abc+");
        assert!(r.is_ok());
    }
}
