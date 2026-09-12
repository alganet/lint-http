// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::helpers::headers::{combined_field_value_as_written, trim_ows};
use crate::helpers::list::{
    list_members_as_written, quoting_is_balanced, split_semicolons_respecting_quotes,
};
use crate::helpers::quoted_string::unescape_quoted_string;
use crate::helpers::shown::{describe_char, shown_in_finding};
use crate::helpers::word::{token_or_quoted_string, WordDefect};
use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::alt_svc::{
    ALT_SVC_ALTERNATIVE_EQUALS_MISSING, ALT_SVC_CLEAR_CONFLICTING,
    ALT_SVC_EQUALS_WHITESPACE_FORBIDDEN, ALT_SVC_PARAMETER_EMPTY, ALT_SVC_PARAMETER_EQUALS_MISSING,
    ALT_SVC_PARAMETER_VALUE_EMPTY, RFC_7838_3,
};
use crate::violations::list::{
    LIST_MEMBER_EMPTY, LIST_MEMBER_MISSING, RFC_9110_5_6_1_1, RFC_9110_5_6_1_2,
};
use crate::violations::quoted_pair::QUOTED_PAIR_MALFORMED;
use crate::violations::quoted_string::{
    quoted_string_defect, QUOTED_STRING_CONTROL_CHARACTER_FORBIDDEN,
    QUOTED_STRING_DELIMITER_MISSING, QUOTED_STRING_QUOTE_ESCAPE_MISSING, RFC_9110_5_6_4,
};
use crate::violations::token::{
    token_character, RFC_9110_5_6_2, TOKEN_CHARACTER_FORBIDDEN, TOKEN_EMPTY,
    TOKEN_WHITESPACE_OR_CONTROL_FORBIDDEN,
};
use crate::violations::uri::{
    percent_encoding, uri_host, PERCENT_ENCODING_DIGITS_MISSING, PERCENT_ENCODING_MALFORMED,
    RFC_3986_2_1, RFC_3986_3_2_2, RFC_3986_3_2_3, URI_HOST_BRACKET_FORBIDDEN,
    URI_HOST_CHARACTER_FORBIDDEN, URI_HOST_CLOSING_BRACKET_MISSING, URI_HOST_IP_LITERAL_MALFORMED,
    URI_PORT_CHARACTER_FORBIDDEN,
};
use crate::violations::ViolationDef;

/// Twenty-two defects over five subjects, and RFC 7838 defines six of them.
///
/// The six are the field's own: the alternation at the top of it, the two `=`
/// delimiters it prints, the whitespace it prints nowhere near them, and the
/// two halves a parameter can be written without. Everything else here is
/// imported, and the paragraph below is where each import comes from.
///
/// § 1.1 says where the notation comes from and § 3 says where the productions
/// do: the `#rule` extension is RFC 7230 § 7's, whose sender requirement is the
/// one RFC 9110 § 5.6.1.1 now carries; `protocol-id` and a parameter's name are
/// `token`; an `alt-authority` and a parameter's value may be a
/// `quoted-string`; and the content inside those DQUOTEs is a `uri-host` and a
/// `port` out of RFC 3986. So an `alt-authority` of `"a]b:443"` reports the
/// same defect a `Forwarded` `for=` and a `Warning`'s `warn-agent` do.
///
/// **Seven findings stay this document's and are not named yet.** Two are the
/// ALPN name's percent-encoding spelling, which is this field's alone; two are
/// `alt-authority`'s prose, which requires the colon and the port the ABNF
/// leaves optional; one is a port outside the sixteen-bit namespace an ALPN
/// name implies; one is `persist`'s single literal; and one is § 8's A-labels.
/// Every one is a sentence about `Alt-Svc` and no other field, so every one of
/// them is the `alt_svc` subject's, as the six already there were.
///
/// **Nothing here borrows from the `parameter` subject, and the reason is one
/// sentence repeated three times.** RFC 7838 § 3's `parameter` is not
/// § 5.6.6's: its value is mandatory where § 5.6.6's is optional, it prints no
/// whitespace beside its `=` at all, and the repetition holding it brackets
/// nothing where § 5.6.6 writes `[ parameter ]`. So a bare name, a spaced-out
/// `=` and an empty repetition are three defects here and none there, and where
/// § 5.6.6 tolerates the whitespace at `info` this document admits none and
/// says so at `warn`. **A production of the same name in another document is
/// another production**, and the catalogue holds both without either borrowing
/// the other's sentence.
///
/// **Three of the four `quoted_string_*` entries are declared and unreachable
/// here, and the reason is a check two levels up.** The field value's quoting
/// is measured for balance before any member is cut, so an unescaped DQUOTE and
/// a trailing backslash are both reported there as the missing delimiter; a
/// control octet cannot enter a `hyper::HeaderValue` at all. The mapping is
/// exhaustive regardless — the grammar's reader is where the grammar's question
/// is answered — and `uri_host_closing_bracket_missing` is nearly the same
/// story from the other side: it needs a `]` that is not where the host ends,
/// because a literal that never closes leaves the composition with no port to
/// find and is reported as that instead.
static DECLARED: &[&ViolationDef] = &[
    &ALT_SVC_CLEAR_CONFLICTING,
    &ALT_SVC_ALTERNATIVE_EQUALS_MISSING,
    &ALT_SVC_PARAMETER_EQUALS_MISSING,
    &ALT_SVC_PARAMETER_EMPTY,
    &ALT_SVC_PARAMETER_VALUE_EMPTY,
    &ALT_SVC_EQUALS_WHITESPACE_FORBIDDEN,
    &LIST_MEMBER_EMPTY,
    &LIST_MEMBER_MISSING,
    &TOKEN_EMPTY,
    &TOKEN_CHARACTER_FORBIDDEN,
    &TOKEN_WHITESPACE_OR_CONTROL_FORBIDDEN,
    &QUOTED_STRING_DELIMITER_MISSING,
    &QUOTED_PAIR_MALFORMED,
    &QUOTED_STRING_QUOTE_ESCAPE_MISSING,
    &QUOTED_STRING_CONTROL_CHARACTER_FORBIDDEN,
    &PERCENT_ENCODING_DIGITS_MISSING,
    &PERCENT_ENCODING_MALFORMED,
    &URI_HOST_CLOSING_BRACKET_MISSING,
    &URI_HOST_IP_LITERAL_MALFORMED,
    &URI_HOST_BRACKET_FORBIDDEN,
    &URI_HOST_CHARACTER_FORBIDDEN,
    &URI_PORT_CHARACTER_FORBIDDEN,
];

/// One finding from the reading, and the defect it reports as where the
/// catalogue names that defect.
///
/// The shape `expect_header_valid` settled: a judge that is half converted says
/// so in its type. Here the halves are five subjects' ids — four imported and
/// this field's own — against the seven sentences RFC 7838 writes about
/// `Alt-Svc` that no entry holds yet.
struct Defect {
    def: Option<&'static ViolationDef>,
    message: String,
}

impl Defect {
    /// A defect the catalogue names.
    fn named(def: &'static ViolationDef, message: String) -> Self {
        Self {
            def: Some(def),
            message,
        }
    }

    /// A defect no subject has claimed, reported at the rule's severity the way
    /// every finding here was before the catalogue existed.
    fn unnamed(message: String) -> Self {
        Self { def: None, message }
    }

    /// The same defect with its message read from further out -- which
    /// `protocol-id` the spelling belonged to, which member of the list.
    fn in_context(self, context: impl FnOnce(String) -> String) -> Self {
        Self {
            def: self.def,
            message: context(self.message),
        }
    }
}

/// The one alternative of the field's top production that is not a list.
///
/// `%s` is RFC 7405's case-sensitive string, and the comment beside it says so
/// twice over -- so `Clear` is not this keyword, and the value carrying it is
/// read as an `alt-value` like any other.
// cite(RFC 7838 § 3, label: Alt-Svc grammar): "Alt-Svc       = clear / 1#alt-value"
// cite(RFC 7838 § 3): "clear         = %s"clear"; "clear", case-sensitive"
// cite(RFC 7838 § 3): "The field value consists either of a list of values, each of which indicates one alternative service, or the keyword "clear"."
const CLEAR: &str = "clear";

/// The whitespace neither `alternative` nor `parameter` prints around its `=`.
///
/// RFC 7838 writes `OWS` in exactly one place -- around the semicolon of
/// `*( OWS ";" OWS parameter )` -- and the `#rule` it imports prints it around
/// the commas. Both are gone by the time a half arrives here. So whitespace
/// still touching an `=` is admitted by no production, and this is the
/// *opposite* answer to the one a `BWS` would give: `BWS` is whitespace a
/// grammar tolerates for historical reasons, and there is none printed here to
/// tolerate.
// cite(RFC 7838 § 3): "alt-value     = alternative *( OWS ";" OWS parameter )"
// cite(RFC 9110 § 5.6.3, label: OWS grammar): "OWS            = *( SP / HTAB )"
fn whitespace_beside_delimiter(left: &str, right: &str) -> bool {
    left.ends_with([' ', '\t']) || right.starts_with([' ', '\t'])
}

/// The three sentences RFC 7838 § 3 adds on top of `protocol-id = token`.
///
/// A `token` admits `%`, so the character scan cannot see any of them. Each is
/// a MUST or a MUST NOT addressed to whoever writes the field, and together
/// they are what the section's closing sentence rests on -- *"With these
/// constraints, recipients can apply simple string comparison to match protocol
/// identifiers."* A protocol-id spelled two ways is two protocols to every
/// recipient reading it that way.
///
/// `helpers::uri::check_percent_encoding` declines the uppercase question on
/// purpose: RFC 3986 § 2.1 asks for uppercase as a *consistency* preference and
/// says the two cases are equivalent. That decline is right for a URI and wrong
/// here, because this document states it as a MUST for this one production.
// cite(RFC 7838 § 3): "Octets not allowed in tokens ([RFC7230], Section 3.2.6) MUST be percent-encoded as per Section 2.1 of [RFC3986]."
// cite(RFC 7838 § 3): "Consequently, the octet representing the percent character "%" (hex 25) MUST be percent-encoded as well."
// cite(RFC 7838 § 3): "In order to have precisely one way to represent any ALPN protocol name, the following additional constraints apply:"
// cite(RFC 7838 § 3): "Octets in the ALPN protocol name MUST NOT be percent-encoded if they are valid token characters except "%", and"
// cite(RFC 7838 § 3): "When using percent-encoding, uppercase hex digits MUST be used."
// cite(RFC 7838 § 3): "With these constraints, recipients can apply simple string comparison to match protocol identifiers."
// cite(RFC 3986 § 2.1): "pct-encoded = "%" HEXDIG HEXDIG"
fn protocol_id_encoding_defect(protocol_id: &str) -> Option<Defect> {
    // The triplet's *shape* is `helpers::uri::percent_encoding_defect`'s, and it
    // is asked first so that everything below can take two hex digits for
    // granted. It also answers a case this rule would otherwise have to
    // re-derive: a '%' whose next bytes begin a multi-byte character, which it
    // reports by taking three *characters* rather than three bytes.
    //
    // The shape is `pct-encoded`'s and reports as such; everything below is
    // this field's own spelling rule for an ALPN name and reports as nothing.
    if let Some(defect) = crate::helpers::uri::percent_encoding_defect(protocol_id) {
        return Some(Defect::named(
            percent_encoding(defect),
            format!(
                "{} -- and the octet representing '%' is itself required to be written `%25`",
                defect.message()
            ),
        ));
    }

    let bytes = protocol_id.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] != b'%' {
            i += 1;
            continue;
        }
        // Both are `HEXDIG`; the scan above returned `None`.
        let (hi, lo) = (bytes[i + 1] as char, bytes[i + 2] as char);
        if hi.is_ascii_lowercase() || lo.is_ascii_lowercase() {
            return Some(Defect::unnamed(format!(
                "the triplet '%{hi}{lo}' at offset {i} uses lowercase hex digits, and this field requires uppercase ones so that two spellings of one ALPN protocol name cannot exist"
            )));
        }
        // The escaping table's third row is why `%25` is exempt: `%` is a
        // `tchar`, and it is the one `tchar` this document requires to be
        // encoded rather than forbids.
        let octet = (hi.to_digit(16)? * 16 + lo.to_digit(16)?) as u8;
        if octet != b'%' && crate::helpers::token::is_tchar_byte(octet) {
            return Some(Defect::unnamed(format!(
                "the triplet '%{hi}{lo}' at offset {i} encodes {}, which is a `tchar` and so must appear as itself -- this field admits exactly one spelling per ALPN protocol name",
                describe_char(octet as char)
            )));
        }
        i += 3;
    }
    None
}

/// `Alt-Svc` names an origin's alternative services, and this rule reads the
/// field value against the grammar RFC 7838 § 3 prints for it.
pub struct AltSvcHeaderSyntax;

/// `alt-authority = quoted-string ; containing [ uri-host ] ":" port`
///
/// Two productions deep, and the outer one is where this rule used to stop:
/// the DQUOTEs are the production, not a style, which the section says in as
/// many words when it explains why its own examples carry them. The inner
/// content is prose rather than ABNF, and it is prose that *requires* both
/// the colon and the number while leaving the host optional -- the same
/// shape as `authority-form`, where the quantifiers demand nothing and the
/// sentence beside them demands two halves.
// cite(RFC 7838 § 3): "alt-authority = quoted-string ; containing [ uri-host ] ":" port"
// cite(RFC 7838 § 3): "The "alt-authority" component consists of an OPTIONAL uri-host ("host" in Section 3.2.2 of [RFC3986]), a colon (":"), and a port number."
// cite(RFC 7838 § 3): "Note that the "quoted-string" syntax needs to be used because ":" is not an allowed character in "token"."
// cite(RFC 9110 § 5.6.4): "quoted-string  = DQUOTE *( qdtext / quoted-pair ) DQUOTE"
fn check_alt_authority(shown: &str, authority: &str) -> Option<Defect> {
    if !authority.starts_with('"') {
        // The production is its two DQUOTEs and what they enclose, so a value
        // with neither is not a badly-written `alt-authority` but a
        // `quoted-string` missing a delimiter -- which is the def's own
        // sentence, and the reason this rule and six others report it alike.
        return Some(Defect::named(
            &QUOTED_STRING_DELIMITER_MISSING,
            format!(
                "Alt-Svc alternative '{shown}' carries an unquoted alt-authority. `alt-authority` is a `quoted-string`, and the DQUOTEs are what let it hold the colon at all -- ':' is in no `token`, so a recipient reading this against the grammar finds the alternative ends at the '='"
            ),
        ));
    }
    // `unescape_quoted_string` opens with the validation, so asking for it
    // separately would run the same walk twice and leave a discarded `Err`
    // behind -- which reads as an early exit and can never fire.
    let inner = match unescape_quoted_string(authority) {
        Ok(inner) => inner,
        Err(defect) => {
            let message = defect.message(authority);
            return Some(Defect::named(
                quoted_string_defect(defect),
                format!(
                    "Alt-Svc alternative '{shown}' carries an alt-authority that is not a well-formed `quoted-string`: {message}"
                ),
            ));
        }
    };

    // Every production the content derives from is US-ASCII -- `reg-name`
    // is `*( unreserved / pct-encoded / sub-delims )` and `port` is
    // `*DIGIT` -- so an octet at or above %x80 belongs to none of them.
    // § 8 names the reason it is usually there and forbids it by name.
    // cite(RFC 7838 § 8): "An internationalized domain name that appears in either the header field (Section 3) or the HTTP/2 frame (Section 4) MUST be expressed using A-labels ([RFC5890], Section 2.3.2.1)."
    // cite(RFC 3986 § 3.2.2): "reg-name    = *( unreserved / pct-encoded / sub-delims )"
    //
    // Unnamed, and the sentence reported is why. `uri_host_character_forbidden`
    // would answer for a high octet in the *host*, but this is asked of the
    // whole `alt-authority` before it is split, and what it reports is § 8's
    // MUST about how an internationalized name is written *instead* -- a
    // requirement about the sender's spelling, not about which octets a
    // `reg-name` admits. A value that gets past here and still holds one is the
    // host subject's, below.
    if let Some(c) = inner.chars().find(|c| !c.is_ascii()) {
        return Some(Defect::unnamed(format!(
            "Alt-Svc alternative '{shown}' has the octet {} inside its alt-authority. Every production the content derives from is US-ASCII, and an internationalized domain name here is written as A-labels",
            crate::helpers::shown::describe_octet(c as u32 as u8)
        )));
    }

    // `port = *DIGIT` is thirteen characters standing alone between two
    // paragraphs, which is under the extractor's floor; the sentence beside
    // it is what carries the production, and it names the delimiter this
    // split is looking for.
    // cite(RFC 3986 § 3.2.3): "The port subcomponent of authority is designated by an optional port number in decimal following the host and delimited from it by a single colon (":") character."
    let (host, port) = crate::helpers::uri::split_host_and_port(&inner);
    let Some(port) = port else {
        // The prose beside the production, and it is this document's: the two
        // halves are RFC 3986's and which of them is optional is § 3's.
        return Some(Defect::unnamed(format!(
            "Alt-Svc alternative '{shown}' has an alt-authority with no ':' in it. The host is optional and the colon and the port number are not, so '{}' names no port for a client to open the alternative on",
            shown_in_finding(&inner)
        )));
    };
    if !host.is_empty() {
        if let Err(defect) = crate::helpers::uri::validate_uri_host(host) {
            let message = defect.message();
            return Some(Defect::named(
                uri_host(defect),
                format!(
                    "Alt-Svc alternative '{shown}' has an alt-authority whose host is not a `uri-host`: {message}"
                ),
            ));
        }
    }
    if port.is_empty() {
        // Said in the finding itself: `port = *DIGIT` generates this, so no
        // production is broken and there is no defect of one to report. What is
        // wrong is § 3's prose asking for a port number.
        return Some(Defect::unnamed(format!(
            "Alt-Svc alternative '{shown}' carries the port's delimiter and no port. `port` is `*DIGIT`, so the grammar admits this, and the sentence beside it asks for a port number -- a client reading this has a host and no number to reach it on"
        )));
    }
    if let Some(c) = port.chars().find(|c| !c.is_ascii_digit()) {
        return Some(Defect::named(
            &URI_PORT_CHARACTER_FORBIDDEN,
            format!(
                "Alt-Svc alternative '{shown}' has {} in its port, which derives from no `port` -- the production is `*DIGIT`",
                describe_char(c)
            ),
        ));
    }
    // The bound is not the grammar's; `port = *DIGIT` has none. It is that
    // an ALPN protocol name identifies a protocol suite carried over a
    // transport whose port registries are sixteen bits wide. `0` sits
    // *inside* that namespace as a reserved edge value, and no sentence
    // here makes a reserved port an invalid one.
    // cite(RFC 7838 § 2): "Note that for the purpose of this specification, an ALPN protocol name implicitly includes TLS in the suite of protocols it identifies, unless specified otherwise in its definition."
    // cite(RFC 6335 § 6): "TCP, UDP, UDP-Lite, SCTP, and DCCP use 16-bit namespaces for their port number registries."
    // cite(RFC 6335 § 6): "Reserved port numbers include values at the edges of each range, e.g., 0, 1023, 1024, etc., which may be used to extend these ranges or the overall port number space in the future."
    if crate::helpers::uri::port_number(port).is_none() {
        // A well-formed `port` naming a number no transport has. The def above
        // is about the octets and says in its own doc that a port outside a
        // transport's range is not its finding, because `port = *DIGIT` bounds
        // nothing -- so the sentence answering this one is RFC 6335's, and the
        // subject that would hold it does not exist.
        return Some(Defect::unnamed(format!(
            "Alt-Svc alternative '{shown}' names port {port}, which designates no port: the transports an ALPN protocol name is carried over register theirs in a sixteen-bit namespace"
        )));
    }
    None
}

/// `parameter = token "=" ( token / quoted-string )`
///
/// The name half is read and the value half is read, and neither is looked
/// up: *"Unknown parameters MUST be ignored"* is what a recipient does with
/// a name it does not know, so a name it does not know is not a defect.
/// `persist` is the exception, and only because § 3.1 prints a syntax for
/// it that is one literal wide.
///
/// This is deliberately **not** `helpers::headers::parse_token_bws_word`, and
/// the tell is the one that answered the same question for `keepalive-param`:
/// that helper owns `token [ BWS "=" BWS word ]`, and this production writes
/// neither of the two things making it that shape. There is no `BWS` -- RFC
/// 7838 prints `OWS` around its semicolon and nowhere else, so whitespace
/// beside this `=` is a defect where the helper's is a tolerated historical
/// artefact it reports separately; and the optional group is not optional
/// here, so a bare `ma` is a finding rather than a name with no value. Three
/// independent reviews have now proposed the fold; the two grammars disagree
/// on both halves, which is what `BWS` is a tell for in either direction.
///
/// P2 settled it by folding the half that does *not* disagree. The value is
/// `( token / quoted-string )` -- the same pair RFC 7838 imports from RFC 7230
/// by name and RFC 9110 carries unchanged -- so the alternation is read by
/// `helpers::headers::token_or_quoted_string` and every sentence about what it
/// found is still this field's. The name, the `=` and the whitespace beside it
/// stay here, because that is where this document differs from the other two.
// cite(RFC 7838 § 3): "parameter     = token "=" ( token / quoted-string )"
// cite(RFC 7838 § 3): "Each "alt-value" is followed by an OPTIONAL semicolon-separated list of additional parameters, each such "parameter" comprising a name and a value."
// cite(RFC 7838 § 3): "Unknown parameters MUST be ignored."
fn check_parameter(shown: &str, parameter: &str) -> Option<Defect> {
    // `*( OWS ";" OWS parameter )` repeats a group holding one parameter,
    // so two adjacent semicolons produce a repetition with nothing in it.
    // The brackets § 5.6.6 puts around its own `[ parameter ]` are what makes
    // that conforming there and a defect here, which is why the entry is this
    // field's rather than that subject's.
    if parameter.is_empty() {
        return Some(Defect::named(
            &ALT_SVC_PARAMETER_EMPTY,
            format!(
                "Alt-Svc alt-value '{shown}' carries a semicolon with no parameter after it. Each repetition of `*( OWS \";\" OWS parameter )` holds one `parameter`, and a `parameter` is a name, an '=' and a value"
            ),
        ));
    }
    //
    // **Not `parameter_equals_missing`.** That def carries § 5.6.6's
    // `parameter`, whose value the constructs reading it treat as optional --
    // which is the very thing the paragraph above says this production is not.
    // A def is a sentence, and this field's is its own -- so it has one of its
    // own, and the two ids sit beside each other in the catalogue saying which
    // document each answers for.
    let Some((name, value)) = parameter.split_once('=') else {
        return Some(Defect::named(
            &ALT_SVC_PARAMETER_EQUALS_MISSING,
            format!(
                "Alt-Svc parameter '{}' in '{shown}' has no '='. A `parameter` is `token \"=\" ( token / quoted-string )`, so the value and its delimiter are not optional",
                shown_in_finding(parameter)
            ),
        ));
    };
    //
    // **Not `parameter_equals_whitespace_forbidden` either**, and this is the
    // sharper half of the same refusal: that def is `info`, because § 5.6.6's
    // readers trim the whitespace and publish the leniency. This document
    // prints no whitespace here to be lenient *about*, so the finding reports
    // as this field's own defect at this field's own rank.
    if whitespace_beside_delimiter(name, value) {
        return Some(Defect::named(
            &ALT_SVC_EQUALS_WHITESPACE_FORBIDDEN,
            format!(
                "Alt-Svc parameter '{}' in '{shown}' has whitespace beside its '='. `parameter` prints `token \"=\" ( token / quoted-string )` with nothing between the halves and the delimiter, and the only `OWS` this grammar writes sits around the semicolon",
                shown_in_finding(parameter)
            ),
        ));
    }
    if name.is_empty() {
        return Some(Defect::named(
            &TOKEN_EMPTY,
            format!(
                "Alt-Svc parameter '{}' in '{shown}' has no name. `token` is `1*tchar`, so it derives no empty string",
                shown_in_finding(parameter)
            ),
        ));
    }
    if let Some(c) = crate::helpers::token::find_invalid_token_char(name) {
        return Some(Defect::named(
            token_character(c),
            format!(
                "Alt-Svc parameter name '{}' in '{shown}' holds {}, which is no `tchar`",
                shown_in_finding(name),
                describe_char(c)
            ),
        ));
    }
    // The value half is `( token / quoted-string )`, read by the shared reader
    // that owns the alternation; every sentence below is this field's own answer
    // to what the reader found, because "empty" in particular is a verdict two
    // other rules in this tree deliberately do not share.
    let unquoted = match token_or_quoted_string(value) {
        Ok(content) => content,
        // The `None` `word_defect` answers, at the third of the six fields that
        // reach it: what an empty value means is this field's verdict, and this
        // field now has an entry to say it in.
        Err(WordDefect::Empty) => {
            return Some(Defect::named(
                &ALT_SVC_PARAMETER_VALUE_EMPTY,
                format!(
                    "Alt-Svc parameter '{}' in '{shown}' has an empty value. The value half is `token / quoted-string`, and the empty string derives from neither -- a `token` is `1*tchar` and a `quoted-string` is at least its two DQUOTEs",
                    shown_in_finding(name)
                ),
            ))
        }
        Err(WordDefect::NotToken(c)) => {
            return Some(Defect::named(
                token_character(c),
                format!(
                    "Alt-Svc parameter '{}' in '{shown}' has {} in an unquoted value. The value half is `token / quoted-string`, so a character no `tchar` admits has to be written inside DQUOTEs",
                    shown_in_finding(name),
                    describe_char(c)
                ),
            ))
        }
        Err(WordDefect::NotQuotedString(defect)) => {
            let message = defect.message(value);
            return Some(Defect::named(
                quoted_string_defect(defect),
                format!(
                    "Alt-Svc parameter '{}' in '{shown}' has a value that is not a well-formed `quoted-string`: {message}",
                    shown_in_finding(name)
                ),
            ))
        }
    };

    // § 3.1 prints a syntax for this parameter, and the syntax is one
    // literal. The sentence beside it is addressed to clients rather than
    // to the sender, which is what makes the finding a report of what the
    // value will be treated as rather than of a refusal.
    // cite(RFC 7838 § 3.1): "Alternative services that are intended to be longer lived (such as those that are not specific to the client access network) can carry the "persist" parameter with a value "1" as a hint that the service is potentially useful beyond a network configuration change."
    // cite(RFC 7838 § 3.1): "This specification only defines a single value for "persist"."
    // cite(RFC 7838 § 3.1): "Clients MUST ignore "persist" parameters with values other than "1"."
    if name == "persist" && unquoted != "1" {
        return Some(Defect::unnamed(format!(
            "Alt-Svc alt-value '{shown}' sets persist to '{}'. The registered syntax for this parameter is the single literal \"1\", and a client is required to ignore every other value -- so this alternative carries no persistence hint at all",
            shown_in_finding(&unquoted)
        )));
    }
    None
}

/// One `alt-value = alternative *( OWS ";" OWS parameter )`.
fn check_alt_value(member: &str) -> Option<Defect> {
    let shown = shown_in_finding(member);
    // The splitter always pushes a trailing segment, so there is always a
    // first one; `alt-value` is an `alternative` with the parameter group
    // behind it.
    let parts = split_semicolons_respecting_quotes(member);
    let (alternative, parameters) = parts
        .split_first()
        .expect("the splitter yields at least one segment");

    // The first `=` is the delimiter and not a guess: `protocol-id` is a
    // `token`, `=` is not a `tchar`, and RFC 7838's own escaping table prints
    // the ALPN name `w=x:y#z` as the `protocol-id` `w%3Dx%3Ay#z` -- the
    // character is spelled `%3D` on the left of the delimiter or it is the
    // delimiter. Anything the right half holds is inside the `quoted-string`
    // that starts after it.
    // cite(RFC 7838 § 3): "alternative   = protocol-id "=" alt-authority"
    // cite(RFC 7838 § 3): "protocol-id   = token ; percent-encoded ALPN protocol name"
    // cite(RFC 9110 § 5.6.2): "token = 1*tchar tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA"
    let Some((protocol_id, authority)) = alternative.split_once('=') else {
        // `%s"clear"` is case-sensitive, so a case variant is not the
        // keyword -- it is an `alt-value` with no '=' in it, and saying so
        // is more use to whoever wrote it than the generic verdict. **The id
        // is the same one either way**: what the value is does not change
        // because a reader can say how its sender got there.
        // cite(RFC 7838 § 3): "clear         = %s"clear"; "clear", case-sensitive"
        if alternative.eq_ignore_ascii_case(CLEAR) {
            return Some(Defect::named(
                &ALT_SVC_ALTERNATIVE_EQUALS_MISSING,
                format!(
                    "Alt-Svc carries '{}' where the keyword is spelled `%s\"clear\"` -- a case-sensitive string, so this value is read as an `alt-value` instead, and an `alt-value` opens with `protocol-id \"=\" alt-authority`",
                    shown_in_finding(alternative)
                ),
            ));
        }
        return Some(Defect::named(
            &ALT_SVC_ALTERNATIVE_EQUALS_MISSING,
            format!(
                "Alt-Svc alt-value '{shown}' has no '=' in its alternative. `alternative` is `protocol-id \"=\" alt-authority`, so a recipient reading this finds a protocol identifier and no alternative to reach it at"
            ),
        ));
    };
    if whitespace_beside_delimiter(protocol_id, authority) {
        return Some(Defect::named(
            &ALT_SVC_EQUALS_WHITESPACE_FORBIDDEN,
            format!(
                "Alt-Svc alt-value '{shown}' has whitespace beside the '=' of its alternative. `alternative` prints `protocol-id \"=\" alt-authority` with nothing between the halves and the delimiter, and the only `OWS` this grammar writes sits around the semicolon before a parameter"
            ),
        ));
    }
    if protocol_id.is_empty() {
        return Some(Defect::named(
            &TOKEN_EMPTY,
            format!(
                "Alt-Svc alt-value '{shown}' has an empty protocol-id. `protocol-id` is a `token`, and `token` is `1*tchar`"
            ),
        ));
    }
    if let Some(c) = crate::helpers::token::find_invalid_token_char(protocol_id) {
        return Some(Defect::named(
            token_character(c),
            format!(
                "Alt-Svc protocol-id '{}' holds {}, which is no `tchar`. An ALPN protocol name is an octet sequence with no constraints of its own, so anything a `token` will not carry is written percent-encoded",
                shown_in_finding(protocol_id),
                describe_char(c)
            ),
        ));
    }
    if let Some(defect) = protocol_id_encoding_defect(protocol_id) {
        return Some(defect.in_context(|message| {
            format!(
                "Alt-Svc protocol-id '{}' is not the one spelling this field allows for its ALPN protocol name: {message}",
                shown_in_finding(protocol_id)
            )
        }));
    }
    if let Some(defect) = check_alt_authority(&shown, authority) {
        return Some(defect);
    }
    for parameter in parameters {
        if let Some(defect) = check_parameter(&shown, parameter) {
            return Some(defect);
        }
    }
    None
}

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
///
/// § 3 is not among them: it belongs to the entry that names it, so it is
/// defined in `violations/alt_svc.rs` beside that entry's quote and imported
/// back here. A reference on a def and a reference in `specifications()` are
/// compared by value, so there is one definition or there is a silent split.
const RFC_7838_3_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 7838",
    section: Some("3.1"),
    url: "https://www.rfc-editor.org/rfc/rfc7838.html#section-3.1",
    note: "Caching Alt-Svc Header Field Values: `persist = \"1\"` is the whole syntax of that parameter, and clients ignore any other value",
};
const RFC_7838_1_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 7838",
    section: Some("1.1"),
    url: "https://www.rfc-editor.org/rfc/rfc7838.html#section-1.1",
    note: "Notational Conventions: the field's terminals — `OWS`, `port`, `quoted-string`, `token`, `uri-host` — and the `#rule` extension are imported from RFC 7230, whose §3.2.3, §2.7, §3.2.6 and §7 are carried unchanged by RFC 9110 §5.6.3, §4.1, §5.6.4, §5.6.2 and §5.6.1",
};
const RFC_7838_8: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 7838",
    section: Some("8"),
    url: "https://www.rfc-editor.org/rfc/rfc7838.html#section-8",
    note: "Internationalization Considerations: an internationalized domain name in this field is written as A-labels",
};
const RFC_7838_2: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 7838",
    section: Some("2"),
    url: "https://www.rfc-editor.org/rfc/rfc7838.html#section-2",
    note: "Alternative Services Concepts: an alternative service is an ALPN protocol name, an RFC 3986 host and an RFC 3986 port, and the protocol name implies the transport the port is registered in",
};
const RFC_9110_5_6_3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9110",
    section: Some("5.6.3"),
    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.3",
    note: "Whitespace: `OWS`, which this field's grammar prints around its semicolon and around the list's commas — and, by printing it in exactly those two places, nowhere else. The four productions the grammar is otherwise built from are the subsections listed beside this one, each named by the defect it answers for",
};
const RFC_6335_6: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 6335",
    section: Some("6"),
    url: "https://www.rfc-editor.org/rfc/rfc6335.html#section-6",
    note: "Port Number Ranges: the sixteen-bit namespace that bounds the port, and the reserved edge values that are not thereby invalid",
};

impl RuleMeta for AltSvcHeaderSyntax {
    fn id(&self) -> &'static str {
        "alt_svc_header_syntax"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
severity = "warn"
"#
    }

    fn title(&self) -> Option<&'static str> {
        Some("Server Alt-Svc Header Syntax")
    }

    fn description(&self) -> &'static str {
        "Read an `Alt-Svc` response header field against the grammar RFC 7838 §3 prints for it:\n\n```\nAlt-Svc       = clear / 1#alt-value\nclear         = %s\"clear\"; \"clear\", case-sensitive\nalt-value     = alternative *( OWS \";\" OWS parameter )\nalternative   = protocol-id \"=\" alt-authority\nprotocol-id   = token ; percent-encoded ALPN protocol name\nalt-authority = quoted-string ; containing [ uri-host ] \":\" port\nparameter     = token \"=\" ( token / quoted-string )\n```\n\n**The alt-authority is a `quoted-string`, and the DQUOTEs are the production.** Every example in RFC 7838 carries them, and the section says why: *\"Note that the \"quoted-string\" syntax needs to be used because \":\" is not an allowed character in \"token\".\"* An unquoted `h2=example.com:443` is reported. Inside the quotes the content is asked for in prose rather than ABNF — *\"an OPTIONAL uri-host …, a colon (\":\"), and a port number\"* — so the host may be absent and the colon and the number may not.\n\n**`clear` is the whole field value or it is nothing.** The top production is an alternation, so a value holding the keyword beside an alternative derives from neither half; RFC 7838 §3 calls that *\"an invalid reply\"* in its own parenthetical. The keyword is `%s\"clear\"`, a case-sensitive string, so `CLEAR` is not it and is read as an `alt-value` instead.\n\n**A `protocol-id` is a percent-encoded ALPN protocol name, and three sentences constrain the spelling** — octets no `token` admits MUST be percent-encoded (including `%` itself, as `%25`), octets that *are* valid token characters MUST NOT be, and the hex digits MUST be uppercase. A `token` admits `%`, so a character scan sees none of these. They exist so that *\"recipients can apply simple string comparison to match protocol identifiers\"*, which two spellings of one name would defeat.\n\n**A port above 65535 is reported; `0` is not.** The bound is not the grammar's — `port` is `*DIGIT` — but that an ALPN protocol name identifies a suite carried over a transport whose port registry is sixteen bits wide (RFC 6335 §6). `0` sits inside that namespace as a reserved edge value, and no sentence here makes a reserved port an invalid one.\n\n**Parameters are read as `token \"=\" ( token / quoted-string )` and not looked up.** *\"Unknown parameters MUST be ignored\"*, so a name this rule does not recognise is not a defect. `persist` is the one exception, because §3.1 prints a syntax for it that is a single literal `\"1\"` and requires clients to ignore any other value. The `ma` parameter's own value is read by `alt_svc_h3_advertisement_valid`.\n\n**Whitespace beside an `=` is reported.** RFC 7838 writes `OWS` in exactly one place — around the semicolon before a parameter — and the `#rule` it imports writes it around the commas. Both are gone by the time a half is read, so whitespace still touching an `=` is admitted by nothing. This is the opposite of a `BWS`, which is whitespace a grammar prints in order to tolerate.\n\n**What this rule declines.** RFC 7838 §3 says that over HTTP/2 *\"servers SHOULD instead send an ALTSVC frame\"*, and the next sentence says *\"Alt-Svc header fields remain valid in responses delivered over HTTP/2\"*. The frame is not in a capture, HTTP/3 has no such frame at all and RFC 9114 §3.1.1 has an HTTP/3 server use this field, so the SHOULD is not reported. Nothing here reads *which* protocol a well-spelled `protocol-id` names — `alt_svc_protocol_registered` decodes it back into its ALPN protocol name and asks that against a configured list."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            RFC_7838_3,
            RFC_7838_3_1,
            RFC_7838_1_1,
            RFC_7838_8,
            RFC_7838_2,
            RFC_9110_5_6_1_1,
            RFC_9110_5_6_1_2,
            RFC_9110_5_6_2,
            RFC_9110_5_6_3,
            RFC_9110_5_6_4,
            RFC_3986_2_1,
            RFC_3986_3_2_2,
            RFC_3986_3_2_3,
            RFC_6335_6,
        ]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "Alt-Svc: h2=\":443\"; ma=2592000\nAlt-Svc: h2=\"new.example.org:80\"\nAlt-Svc: h2=\"alt.example.com:8000\", h2=\":443\"\nAlt-Svc: h2=\"[::1]:443\"; persist=1\nAlt-Svc: clear\nAlt-Svc: w%3Dx%3Ay#z=\":443\"",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "Alt-Svc: h2=example.com:443       # alt-authority is a quoted-string\nAlt-Svc: h2=\"example.com\"         # the colon and the port are not optional\nAlt-Svc: h2=\"example.com:notaport\" # port is *DIGIT\nAlt-Svc: h2example.com:443        # no '=' in the alternative\nAlt-Svc: h@=\":443\"                # '@' is no tchar\nAlt-Svc: x%3dy=\":443\"             # hex digits are uppercase\nAlt-Svc: %68%32=\":443\"            # a tchar is not percent-encoded\nAlt-Svc: clear, h2=\":443\"         # clear beside an alternative\nAlt-Svc: h2 = \":443\"              # no OWS beside the '='\nAlt-Svc: h2=\":443\"; persist=2     # persist's only value is \"1\"\nAlt-Svc: ,                        # empty list element",
            },
        ]
    }
}

impl Rule for AltSvcHeaderSyntax {
    /// The field is one an origin server writes onto its own responses, and
    /// RFC 9110 § 3.7 is why a capture of a gateway's answer is measured by the
    /// same sentence.
    // cite(RFC 7838 § 3): "An HTTP(S) origin server can advertise the availability of alternative services to clients by adding an Alt-Svc header field to responses."
    // cite(RFC 9110 § 3.7): "All HTTP requirements applicable to an origin server also apply to the outbound communication of a gateway."
    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Server
    }

    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        // Single-finding body behind an Option: `?` ends it early, and the
        // one finding (or none) becomes the vector.
        let finding = || -> Option<Violation> {
            // No status gate, and the sentence below is the whole reason there is
            // none: every response is a response this field may ride on.
            // cite(RFC 7838 § 3): "Alt-Svc MAY occur in any HTTP response message, regardless of the status code."
            let resp = tx.response.as_ref()?;
            let severity = ctx.severity;

            // One `char` per octet, because the findings below are about what a
            // sender wrote: `to_str` would fold a field carrying `obs-text` into
            // "no such field here", and `obs-text` is admissible inside a
            // `quoted-string` and inadmissible in every other half of this grammar.
            //
            // The join is licensed by one of the field's two alternatives and not
            // by the other -- `1#alt-value` is a comma-separated list and `clear`
            // is a bare keyword -- so a `clear` arriving beside anything else is
            // read below rather than joined into a member and forgotten. That state
            // is one the document names.
            // The separator the sentence names is a comma *and optional whitespace*,
            // and the join here writes the comma alone -- which is why the member
            // walk below trims `OWS` rather than assuming there is none.
            // cite(RFC 9110 § 5.3): "A recipient MAY combine multiple field lines within a field section that have the same field name into one field line, without changing the semantics of the message, by appending each subsequent field line value to the initial field line value in order, separated by a comma (",") and optional whitespace (OWS, defined in Section 5.6.3)."
            let value = combined_field_value_as_written(&resp.headers, "alt-svc")?;
            let value = trim_ows(&value);

            if value == CLEAR {
                return None;
            }

            // A quote that never closes makes the member list untrustworthy: every
            // separator after the stray DQUOTE stops being one, so the count of
            // members and the identity of each is a guess.
            if !quoting_is_balanced(value) {
                return Some(ctx.report_with(
                    &QUOTED_STRING_DELIMITER_MISSING,
                    format!(
                        "Alt-Svc value '{}' has a DQUOTE that never closes. `alt-authority` is a `quoted-string` and a `parameter`'s value may be one, so an unterminated quote leaves every comma and semicolon after it inside a string that has no end",
                        shown_in_finding(value)
                    ),
                ));
            }

            let members = list_members_as_written(value);

            // `1#alt-value` has a floor of one, and the field's other alternative
            // was ruled out above -- so an empty value is neither.
            // cite(RFC 9110 § 5.6.1.2): "#element => [ element ] *( OWS "," OWS [ element ] )"
            if members.iter().all(|m| m.is_empty()) {
                return Some(ctx.report_with(
                    &LIST_MEMBER_MISSING,
                    "Alt-Svc carries an empty field value. The field is either the keyword `clear` or `1#alt-value`, whose floor is one alternative -- so this value is neither, and it advertises nothing".into(),
                ));
            }

            // The parenthetical is the finding, and it is the document's own word
            // for this state: `clear` is the whole field value or it is nothing.
            // The sentence saying so is on the entry, with the recipient
            // behaviour that ranks it above everything else this rule reports.
            if members.contains(&CLEAR) {
                return Some(ctx.report_with(
                    &ALT_SVC_CLEAR_CONFLICTING,
                    format!(
                        "Alt-Svc response carries both the keyword `clear` and alternative services ('{}'). `Alt-Svc = clear / 1#alt-value` is an alternation, so a value holding both derives from neither half -- the document calls this an invalid reply and has a client invalidate the alternatives named beside the keyword",
                        shown_in_finding(value)
                    ),
                ));
            }

            for member in members {
                if member.is_empty() {
                    // The `#rule` this document imports is the one RFC 9110 § 5.6.1
                    // now carries, and both put the requirement on the sender.
                    // cite(RFC 7838 § 1.1): "This document uses the Augmented BNF defined in [RFC5234] and updated by [RFC7405] along with the "#rule" extension defined in Section 7 of [RFC7230]."
                    // cite(RFC 9110 § 5.6.1.1): "In any production that uses the list construct, a sender MUST NOT generate empty list elements."
                    return Some(ctx.report_with(
                        &LIST_MEMBER_EMPTY,
                        format!(
                            "Alt-Svc value '{}' holds an empty list element. A recipient counts the alternatives it can read and drops this one, so what the list advertises and what it looks like differ",
                            shown_in_finding(value)
                        ),
                    ));
                }
                if let Some(defect) = check_alt_value(member) {
                    return Some(match defect.def {
                        Some(def) => ctx.report_with(def, defect.message),
                        None => self.violation(severity, defect.message),
                    });
                }
            }

            None
        };
        Vec::from_iter(finding())
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &AltSvcHeaderSyntax;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn config() -> crate::config::Config {
        crate::test_helpers::make_test_config_with_severity("alt_svc_header_syntax", "warn")
    }

    fn check(tx: &crate::http_transaction::HttpTransaction) -> Option<Violation> {
        crate::test_helpers::run_rule(
            &AltSvcHeaderSyntax,
            tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &config(),
        )
    }

    fn run(headers: &[(&str, &str)]) -> Option<Violation> {
        check(&crate::test_helpers::make_test_transaction_with_response(
            200, headers,
        ))
    }

    fn message(header: &str) -> String {
        run(&[("alt-svc", header)])
            .unwrap_or_else(|| panic!("expected a violation for {header:?}"))
            .message
    }

    /// The document's own worked examples, which the rule reported before this
    /// audit because it made the DQUOTEs optional and never read `clear`.
    #[rstest]
    #[case("h2=\":8000\"")]
    #[case("h2=\"new.example.org:80\"")]
    #[case("h2=\"alt.example.com:8000\", h2=\":443\"")]
    #[case("h2=\":443\"; ma=3600")]
    #[case("h2=\":8000\"; ma=60")]
    #[case("h2=\":443\"; ma=2592000; persist=1")]
    #[case("clear")]
    // The escaping table's three rows, as `protocol-id`s.
    #[case("h2=\":443\"")]
    #[case("w%3Dx%3Ay#z=\":443\"")]
    #[case("x%25y=\":443\"")]
    // A host with no port delimiter is the only optional half.
    #[case("h2=\"[2001:db8::1]:443\"")]
    #[case("h2=\"192.0.2.1:443\"")]
    // An unknown parameter is ignored rather than judged, in either value form.
    #[case("h2=\":443\"; zzz=whatever")]
    #[case("h2=\":443\"; zzz=\"a;b,c\"")]
    // Values seen in the wild: no OWS after the semicolon (it is optional), a
    // draft ALPN token, and the quoted list Google's QUIC advertisement used to
    // carry -- the one the naive comma split tore into three members.
    #[case("h3=\":443\";ma=86400,h3-29=\":443\";ma=86400")]
    #[case("quic=\":443\"; ma=2592000; v=\"46,43\"")]
    #[case("h3=\":443\"; ma=86400, h2=\":443\"; ma=86400")]
    fn conforming_values_draw_nothing(#[case] header: &str) {
        assert!(run(&[("alt-svc", header)]).is_none(), "for {header:?}");
    }

    #[test]
    fn absent_field_and_absent_response_draw_nothing() {
        assert!(run(&[]).is_none());
        let tx = crate::test_helpers::make_test_transaction();
        assert!(check(&tx).is_none());
    }

    /// Each branch's message is pinned, not merely its existence: a finding is
    /// written in two halves here (a verb phrase and the value it is about) and
    /// a test asserting `is_some` cannot see the two disagree.
    ///
    /// The third column is the defect the finding reports as, and the table
    /// splits cleanly in three. Most named rows are a production RFC 7838
    /// imports — the list, the `token`, the `quoted-string`, the `uri-host`,
    /// the `port`, the `pct-encoded` triplet — and the id is the one every
    /// other reader of that production answers with. One named row is the
    /// field's own, `alt_svc_clear_conflicting`, which no other field can
    /// report. An empty row is a sentence RFC 7838 writes about `Alt-Svc` and
    /// nothing else, waiting for the entry that will hold it: which of its `=`
    /// delimiters are mandatory, that it prints no whitespace beside them, how
    /// an ALPN name is spelled, and what `persist` means.
    #[rstest]
    #[case(
        "h2=example.com:443",
        "unquoted alt-authority",
        "quoted_string_delimiter_missing"
    )]
    #[case("h2=\"example.com\"", "no \':\' in it", "")]
    #[case("h2=\"example.com:\"", "carries the port\'s delimiter and no port", "")]
    #[case(
        "h2=\"example.com:notaport\"",
        "in its port",
        "uri_port_character_forbidden"
    )]
    #[case("h2=\"example.com:65536\"", "sixteen-bit namespace", "")]
    #[case(
        "h2=\"exam ple.com:443\"",
        "is not a `uri-host`",
        "uri_host_character_forbidden"
    )]
    // The bracket has to close *somewhere* for the composition's split to find
    // a port at all -- `[::1:443` with no `]` is a value with no colon after
    // the literal, and the row above is what it draws. What reaches this defect
    // is a `]` that is not where the host ends.
    #[case(
        "h2=\"[abc]x:443\"",
        "is not a `uri-host`",
        "uri_host_closing_bracket_missing"
    )]
    #[case(
        "h2=\"[nope]:443\"",
        "is not a `uri-host`",
        "uri_host_ip_literal_malformed"
    )]
    #[case("h2=\"a]b:443\"", "is not a `uri-host`", "uri_host_bracket_forbidden")]
    #[case("h2=\"a%zb:443\"", "is not a `uri-host`", "percent_encoding_malformed")]
    #[case(
        "h2example.com:443",
        "has no \'=\' in its alternative",
        "alt_svc_alternative_equals_missing"
    )]
    #[case("h@=\":443\"", "which is no `tchar`", "token_character_forbidden")]
    #[case("=\":443\"", "empty protocol-id", "token_empty")]
    #[case("x%3dy=\":443\"", "lowercase hex digits", "")]
    #[case(
        "%68%32=\":443\"",
        "which is a `tchar` and so must appear as itself",
        ""
    )]
    #[case(
        "x%zzy=\":443\"",
        "Invalid percent-encoding \'%zz\'",
        "percent_encoding_malformed"
    )]
    #[case(
        "x%4=\":443\"",
        "Percent-encoding incomplete",
        "percent_encoding_digits_missing"
    )]
    #[case(
        "h2 = \":443\"",
        "whitespace beside the \'=\'",
        "alt_svc_equals_whitespace_forbidden"
    )]
    #[case("h2=\":443\"; persist=2", "sets persist to \'2\'", "")]
    #[case("h2=\":443\"; persist=\"0\"", "sets persist to \'0\'", "")]
    #[case(
        "h2=\":443\"; ;",
        "semicolon with no parameter after it",
        "alt_svc_parameter_empty"
    )]
    #[case("h2=\":443\"; ma", "has no \'=\'", "alt_svc_parameter_equals_missing")]
    #[case(
        "h2=\":443\"; ma=",
        "has an empty value",
        "alt_svc_parameter_value_empty"
    )]
    #[case(
        "h2=\":443\"; ma = 60",
        "whitespace beside its \'=\'",
        "alt_svc_equals_whitespace_forbidden"
    )]
    #[case(
        "h2=\":443\"; m@=60",
        "which is no `tchar`",
        "token_character_forbidden"
    )]
    #[case("h2=\":443\"; =60", "has no name", "token_empty")]
    #[case(
        "h2=\":443\"; ma=6 0",
        "in an unquoted value",
        "token_whitespace_or_control_forbidden"
    )]
    #[case(
        "h2=\":443\"; ma=6@0",
        "in an unquoted value",
        "token_character_forbidden"
    )]
    #[case(
        "clear, h2=\":443\"",
        "both the keyword `clear` and alternative services",
        "alt_svc_clear_conflicting"
    )]
    #[case("CLEAR", "case-sensitive string", "alt_svc_alternative_equals_missing")]
    #[case(",", "empty field value", "list_member_missing")]
    #[case("h2=\":443\",", "empty list element", "list_member_empty")]
    #[case(
        "h2=\":443",
        "DQUOTE that never closes",
        "quoted_string_delimiter_missing"
    )]
    fn each_branch_reports_what_it_is_about(
        #[case] header: &str,
        #[case] expected: &str,
        #[case] violation: &str,
    ) {
        let finding =
            run(&[("alt-svc", header)]).unwrap_or_else(|| panic!("no finding for {header:?}"));
        assert!(
            finding.message.contains(expected),
            "for {header:?} expected {expected:?} in {:?}",
            finding.message
        );
        assert_eq!(finding.violation, violation, "for {header:?}");
    }

    /// `port = *DIGIT` has no bound, and the sixteen-bit one this rule applies
    /// comes from the transport rather than the grammar. RFC 6335 §6 puts `0`
    /// inside that namespace as a reserved value, and reserved is not invalid.
    #[test]
    fn port_zero_is_reserved_rather_than_invalid() {
        assert!(run(&[("alt-svc", "h2=\"[::1]:0\"")]).is_none());
        assert!(run(&[("alt-svc", "h2=\":65535\"")]).is_none());
    }

    /// A quoted-string may hold a comma and a semicolon, and both splitters
    /// this rule calls step over them. The naive `split(',')` this replaced
    /// tore the value below into three members, two of which derive from
    /// nothing.
    #[test]
    fn a_delimiter_inside_a_quoted_string_is_not_a_delimiter() {
        assert!(run(&[("alt-svc", "h2=\":443\"; zzz=\"a,b;c\"")]).is_none());
        let m = message("h2=\":443\"; zzz=\"a,b;c\", h@=\":80\"");
        assert!(m.contains("h@"), "{m}");
    }

    /// `obs-text` reaches this field through a `quoted-string`, which admits
    /// it. `to_str` folded the whole field into a "non-UTF8 value" report,
    /// which named the message where the truth is about one octet -- and
    /// reported a parameter value that is conforming.
    #[test]
    fn obs_text_is_read_where_it_lands_rather_than_refusing_the_field() {
        use hyper::header::HeaderValue;
        use hyper::HeaderMap;

        let mut headers = HeaderMap::new();
        headers.insert(
            "alt-svc",
            HeaderValue::from_bytes(b"h2=\":443\"; zzz=\"\xE9\"")
                .expect("obs-text is a field-content octet"),
        );
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers,
            body_length: None,
            trailers: None,
        });
        assert!(
            check(&tx).is_none(),
            "a quoted-string admits obs-text, and an unknown parameter is ignored"
        );

        let mut headers = HeaderMap::new();
        headers.insert(
            "alt-svc",
            HeaderValue::from_bytes(b"h2=\"\xE9.example.com:443\"")
                .expect("obs-text is a field-content octet"),
        );
        tx.response.as_mut().expect("just built").headers = headers;
        let v = check(&tx).expect("no uri-host derives an octet at or above %x80");
        assert!(v.message.contains("0xE9"), "{}", v.message);
        assert!(v.message.contains("A-labels"), "{}", v.message);
    }

    /// The field's two alternatives are combined differently: a list is one
    /// list however many lines carry it, and the keyword is not a list at all.
    #[test]
    fn clear_on_its_own_line_beside_an_alternative_is_the_invalid_reply() {
        assert!(run(&[("alt-svc", "clear")]).is_none());
        let v = run(&[("alt-svc", "clear"), ("alt-svc", "h2=\":443\"")])
            .expect("the document names this state");
        assert!(
            v.message.contains("invalid reply"),
            "{}",
            v.message.as_str()
        );
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "alt_svc_header_syntax");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[test]
    fn scope_is_server() {
        assert_eq!(AltSvcHeaderSyntax.scope(), crate::rules::RuleScope::Server);
    }
}
