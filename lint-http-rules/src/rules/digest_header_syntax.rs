// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::helpers::shown::{describe_char, shown_in_finding};
use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::base64::{BASE64_MALFORMED, RFC_4648_3_3};
use crate::violations::digest::{
    CONTENT_MD5_OBSOLETE, DIGEST_EQUALS_MISSING, DIGEST_FIELD_OBSOLETE, DIGEST_MEMBER_EMPTY,
    DIGEST_PREFERENCE_INVALID, DIGEST_PREFERENCE_MALFORMED, DIGEST_VALUE_EMPTY,
    DIGEST_VALUE_MALFORMED, RFC_3230_4_2, RFC_7231_APPENDIX_B, RFC_9530, RFC_9530_2, RFC_9530_4,
};
use crate::violations::qvalue::{
    QVALUE_MALFORMED, RFC_9110_12_4_2, WEIGHT_DUPLICATED, WEIGHT_MALFORMED, WEIGHT_MISSING,
};
use crate::violations::structured_fields::{
    structured_field_defect, RFC_9651_3_2, RFC_9651_4_2_2, RFC_9651_4_2_3_1, RFC_9651_4_2_3_3,
    STRUCTURED_FIELD_KEY_MALFORMED, STRUCTURED_FIELD_MEMBER_EMPTY,
    STRUCTURED_FIELD_VALUE_MALFORMED,
};
use crate::violations::token::{
    token_character, RFC_9110_5_6_2, TOKEN_CHARACTER_FORBIDDEN, TOKEN_EMPTY,
    TOKEN_WHITESPACE_OR_CONTROL_FORBIDDEN,
};
use crate::violations::ViolationDef;
use base64::Engine;

pub struct DigestHeaderSyntax;

/// Nineteen defects, eleven of them productions this rule borrows and eight
/// statements the digest documents make — about their own members, and about
/// the two fields that no longer exist.
/// `the_census_above_is_the_declared_list` holds the two numbers.
///
/// RFC 3230 § 4.1.1 writes `digest-algorithm = token` and takes `token` from
/// RFC 2616, whose character set is § 5.6.2's — the fourth reading of that
/// equivalence in this catalogue, and the answer has not changed. So a `Digest`
/// or a `Want-Digest` naming an algorithm no `tchar` admits reports what a
/// `Vary` member and a method do.
///
/// **`Want-Digest` borrows a second production after the algorithm.** § 4.3.1
/// writes `#(digest-algorithm [ ";" "q" "=" qvalue])`, the bracket RFC 9110
/// § 12.4.2 now calls `weight`, so a dangling `;`, a parameter that is not `q`,
/// a second weight and a number that is no `qvalue` are the four defects every
/// field carrying a weight answers with. This reader took the member whole for
/// the algorithm for as long as it existed, and reported each weighted one —
/// the section's own example among them — as a `token` holding a `;`.
///
/// **The RFC 9530 half borrows two things, and the first is the interesting one.**
/// `Content-Digest` and its three siblings are Structured Field Dictionaries,
/// not `#rule` lists: an algorithm is a `key` — lowercase, and the helper that
/// owns that grammar says so — and a value is a Byte Sequence or an Integer. A
/// Dictionary key is emphatically not a `token`, which is the whole point of
/// the finding: carrying RFC 3230's `SHA-256` spelling across produces a field
/// no structured-field parser will read. That defect belongs to RFC 9651's
/// `key` rather than to any of these fields, so it is
/// [`structured_fields`](crate::violations::structured_fields)' — a subject
/// shared by construction, the way `token` is, and one whose second declarer is
/// already visible in `permissions_policy_directives_valid`. The second is a
/// member's parameters, which RFC 9530 never defines and RFC 9651 § 3.2 admits on
/// every member anyway: they are read past rather than taken for the value, and
/// the three ways one fails to derive are that subject's entries too, since no
/// other rule reads these fields.
///
/// **The value half of a member is a subject now**, and it is one subject over
/// both generations: what a `Digest` and a `Content-Digest` carry is the same
/// thing — an algorithm and the digest it produced — so a member with no digest
/// in it is one entry whichever field wrote it, and the encoding under both is
/// [`base64`](crate::violations::base64)'s. What differs is the type the
/// document gives the value, which is why the Byte Sequence and the preference
/// entries name RFC 9530's sections and the empty one names nothing.
///
/// **The empty member is refused on both halves, for two different reasons, and
/// that is why it is two entries.** On the legacy side the list is RFC 2616's
/// `#rule`, which *permits* null elements — the judgment
/// `Sec-WebSocket-Extensions` settled — so `list_member_empty` would report a
/// requirement the field does not carry, and `digest_member_empty` carries no
/// reference at all. On the structured side there is no `#rule`: a comma with
/// nothing beside it fails RFC 9651's parsing loop, which costs the whole
/// field, and that is `structured_field_member_empty`. **One spelling, two
/// documents, two entries** — the same split the missing `=` and the empty name
/// take one line further down.
static DECLARED: &[&ViolationDef] = &[
    &DIGEST_FIELD_OBSOLETE,
    &CONTENT_MD5_OBSOLETE,
    &DIGEST_MEMBER_EMPTY,
    &DIGEST_EQUALS_MISSING,
    &DIGEST_VALUE_MALFORMED,
    &DIGEST_VALUE_EMPTY,
    &DIGEST_PREFERENCE_MALFORMED,
    &DIGEST_PREFERENCE_INVALID,
    &BASE64_MALFORMED,
    &STRUCTURED_FIELD_KEY_MALFORMED,
    &STRUCTURED_FIELD_MEMBER_EMPTY,
    &STRUCTURED_FIELD_VALUE_MALFORMED,
    &TOKEN_EMPTY,
    &TOKEN_CHARACTER_FORBIDDEN,
    &TOKEN_WHITESPACE_OR_CONTROL_FORBIDDEN,
    &QVALUE_MALFORMED,
    &WEIGHT_MISSING,
    &WEIGHT_MALFORMED,
    &WEIGHT_DUPLICATED,
];

/// One finding from the reading, and the defect it reports as where the
/// catalogue names that defect.
///
/// Most of this rule's findings are statements RFC 3230 and RFC 9530 make about
/// their own members and about fields that are gone; the rest are the
/// productions it borrows — `token`, `key`, base64 and the weight — and those
/// answer with the entry the production's own subject declares.
struct Defect {
    def: &'static ViolationDef,
    message: String,
}

impl Defect {
    /// A defect the catalogue names.
    fn named(def: &'static ViolationDef, message: String) -> Self {
        Self { def, message }
    }

    /// The same defect with its message read from further out — which field it
    /// was found in, and on which side.
    fn in_context(self, context: impl FnOnce(String) -> String) -> Self {
        Self {
            def: self.def,
            message: context(self.message),
        }
    }
}

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9530_3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9530",
    section: Some("3"),
    url: "https://www.rfc-editor.org/rfc/rfc9530.html#section-3",
    note: "`Repr-Digest`: the same syntax over representation data rather than message content",
};
const RFC_3230_4_1_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 3230",
    section: Some("4.1.1"),
    url: "https://www.rfc-editor.org/rfc/rfc3230.html#section-4.1.1",
    note: "Historical `Digest` / `Want-Digest`, obsoleted by RFC 9530: `digest-algorithm = token`, case-insensitive — which is why uppercase is valid there and not in the structured fields",
};

const RFC_3230_4_3_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 3230",
    section: Some("4.3.1"),
    url: "https://www.rfc-editor.org/rfc/rfc3230.html#section-4.3.1",
    note: "Historical `Want-Digest`, obsoleted by RFC 9530: `#(digest-algorithm [ \";\" \"q\" \"=\" qvalue])` — each algorithm may carry a weight, in RFC 2616's notation, which lets whitespace stand around the `;` and the `=`",
};

const RFC_9651_2_3: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9651",
    section: Some("2.3"),
    url: "https://www.rfc-editor.org/rfc/rfc9651.html#section-2.3",
    note: "Parameters are the extension point every Item carries, and a field specification is discouraged from making an unrecognized one an error — so a digest member carrying a parameter RFC 9530 never defined is a digest, read without it",
};

/// Which side of the exchange a field is read on.
#[derive(Clone, Copy)]
enum Side {
    Request,
    Response,
}

impl Side {
    /// Who wrote the section this side names. Sound here and not in general:
    /// one field section has exactly one author, which is why the conversion is
    /// written on this rule's own enum rather than as a `From` in core.
    fn party(self) -> crate::lint::Party {
        match self {
            Side::Request => crate::lint::Party::Client,
            Side::Response => crate::lint::Party::Server,
        }
    }
}

impl std::fmt::Display for Side {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Side::Request => "request",
            Side::Response => "response",
        })
    }
}

/// The four grammars the fields in [`FIELDS`] follow.
#[derive(Clone, Copy)]
enum Syntax {
    /// RFC 3230's `Digest`: `alg=base64`, and the algorithm is an ordinary
    /// case-insensitive token rather than a structured-field key.
    LegacyDigest,
    /// RFC 3230's `Want-Digest`: a list of algorithm tokens, each with an
    /// optional weight after it.
    // cite(RFC 3230 § 4.3.1): "Want-Digest = "Want-Digest" ":" #(digest-algorithm [ ";" "q" "=" qvalue])"
    LegacyWantDigest,
    /// RFC 9530's `Content-Digest` / `Repr-Digest`: a Dictionary of
    /// algorithm key to Byte Sequence. The two fields differ only in *what* is
    /// hashed — message content versus representation data — not in syntax, so
    /// one reading serves both.
    // cite(RFC 9530 § 2): "It is a Dictionary (see Section 3.2 of [STRUCTURED-FIELDS]), where each:"
    StructuredDigest,
    /// RFC 9530's `Want-Content-Digest` / `Want-Repr-Digest`: a Dictionary of
    /// algorithm key to weight.
    // cite(RFC 9530 § 4): "Want-Content-Digest and Want-Repr-Digest are of type Dictionary where each:"
    WantPreference,
    /// No grammar at all: the field's presence is the whole finding, so
    /// whatever it says is read and not judged.
    Anything,
}

impl Syntax {
    /// Everything that is wrong with this field value.
    ///
    /// Each of these fields is a list, and each member of one names an
    /// algorithm a sender chose and edits on its own — so a value naming two
    /// algorithms outside the grammar is two names to correct rather than one
    /// finding that happens to have been reached first.
    fn defects(self, value: &str) -> Vec<Defect> {
        match self {
            Syntax::LegacyDigest => legacy_digest_defect(value),
            Syntax::LegacyWantDigest => legacy_want_digest_defect(value),
            Syntax::StructuredDigest => structured_digest_defect(value),
            Syntax::WantPreference => want_preference_defect(value),
            Syntax::Anything => Vec::new(),
        }
    }
}

/// One field this rule reads.
struct Field {
    /// The field name as a lookup key.
    name: &'static str,
    /// The field name as a finding spells it.
    display: &'static str,
    side: Side,
    syntax: Syntax,
    /// What a defect finding names as its authority, in parentheses.
    reference: &'static str,
    /// Set for a field that no longer exists: the finding a well-formed value
    /// still earns, and the entry that says which document retired it.
    obsolete: Option<MemberDefect>,
}

const OBSOLETE_DIGEST: MemberDefect = MemberDefect {
    def: &DIGEST_FIELD_OBSOLETE,
    message: "Digest header is obsoleted by RFC 9530; prefer Content-Digest or Repr-Digest",
};
const OBSOLETE_WANT_DIGEST: MemberDefect = MemberDefect {
    def: &DIGEST_FIELD_OBSOLETE,
    message:
        "Want-Digest header is obsoleted by RFC 9530; prefer Want-Content-Digest or Want-Repr-Digest",
};
/// Content-MD5 is obsolete, but RFC 9530 is not what obsoleted it — that
/// document never mentions the field. It was removed from HTTP by RFC 7231,
/// years earlier, and the entry it reports as carries that sentence. RFC 9530
/// is named only as what to use instead.
const OBSOLETE_CONTENT_MD5: MemberDefect = MemberDefect {
    def: &CONTENT_MD5_OBSOLETE,
    message: "Content-MD5 was removed from HTTP by RFC 7231; use Content-Digest (RFC 9530) instead",
};

/// Every field this rule reads, in the order it reads them — which is the order
/// findings are reported in, so it is the order the rule's tests pin.
const FIELDS: &[Field] = &[
    Field {
        name: "digest",
        display: "Digest",
        side: Side::Request,
        syntax: Syntax::LegacyDigest,
        reference: "obsoleted by RFC 9530",
        obsolete: Some(OBSOLETE_DIGEST),
    },
    Field {
        name: "want-digest",
        display: "Want-Digest",
        side: Side::Request,
        syntax: Syntax::LegacyWantDigest,
        reference: "obsoleted by RFC 9530",
        obsolete: Some(OBSOLETE_WANT_DIGEST),
    },
    Field {
        name: "digest",
        display: "Digest",
        side: Side::Response,
        syntax: Syntax::LegacyDigest,
        reference: "obsoleted by RFC 9530",
        obsolete: Some(OBSOLETE_DIGEST),
    },
    Field {
        name: "content-digest",
        display: "Content-Digest",
        side: Side::Request,
        syntax: Syntax::StructuredDigest,
        reference: "RFC 9530 §2",
        obsolete: None,
    },
    Field {
        name: "repr-digest",
        display: "Repr-Digest",
        side: Side::Request,
        syntax: Syntax::StructuredDigest,
        reference: "RFC 9530 §3",
        obsolete: None,
    },
    Field {
        name: "want-content-digest",
        display: "Want-Content-Digest",
        side: Side::Request,
        syntax: Syntax::WantPreference,
        reference: "RFC 9530 §4",
        obsolete: None,
    },
    Field {
        name: "want-repr-digest",
        display: "Want-Repr-Digest",
        side: Side::Request,
        syntax: Syntax::WantPreference,
        reference: "RFC 9530 §4",
        obsolete: None,
    },
    Field {
        name: "content-digest",
        display: "Content-Digest",
        side: Side::Response,
        syntax: Syntax::StructuredDigest,
        reference: "RFC 9530 §2",
        obsolete: None,
    },
    Field {
        name: "repr-digest",
        display: "Repr-Digest",
        side: Side::Response,
        syntax: Syntax::StructuredDigest,
        reference: "RFC 9530 §3",
        obsolete: None,
    },
    Field {
        name: "want-content-digest",
        display: "Want-Content-Digest",
        side: Side::Response,
        syntax: Syntax::WantPreference,
        reference: "RFC 9530 §4",
        obsolete: None,
    },
    Field {
        name: "want-repr-digest",
        display: "Want-Repr-Digest",
        side: Side::Response,
        syntax: Syntax::WantPreference,
        reference: "RFC 9530 §4",
        obsolete: None,
    },
    // Content-MD5 has no syntax to be wrong: its presence is the finding, so
    // the reading below accepts anything the value says.
    Field {
        name: "content-md5",
        display: "Content-MD5",
        side: Side::Request,
        syntax: Syntax::Anything,
        reference: "removed by RFC 7231",
        obsolete: Some(OBSOLETE_CONTENT_MD5),
    },
    Field {
        name: "content-md5",
        display: "Content-MD5",
        side: Side::Response,
        syntax: Syntax::Anything,
        reference: "removed by RFC 7231",
        obsolete: Some(OBSOLETE_CONTENT_MD5),
    },
];

/// One of the three things that can be wrong with a member before its value is
/// read, as the entry and the wording its caller answers with.
///
/// The caller supplied the wording already; what it supplies now is the id, and
/// it has to, because **the same spelling is a different defect in the two
/// generations**. A comma with nothing beside it is this crate's strictness
/// under RFC 2616's permissive `#rule` and a parse failure in a Dictionary; a
/// bare name is a member missing its `=` in RFC 3230 and a member carrying the
/// Boolean true in RFC 9651; an empty name is a `token` with no character in it
/// and a `key` that starts where no key starts.
#[derive(Clone, Copy)]
struct MemberDefect {
    def: &'static ViolationDef,
    message: &'static str,
}

/// Split a list of `key=value` members, each handed over as written and as the
/// part of it that holds the key and the value.
///
/// The two are the same text for RFC 3230's `Digest`, a `#` list of
/// `alg=base64` with no parameter and no quoted-string anywhere in it, so a
/// bare comma is every separator it has ([`legacy_members`]). They are not the
/// same for RFC 9530's Dictionaries, whose members carry parameters
/// ([`dictionary_members`]), and the wording names what the sender wrote.
fn key_value_members(
    members: Vec<(&str, &str)>,
    empty_member: MemberDefect,
    missing_eq: MemberDefect,
    empty_algorithm: MemberDefect,
) -> (Vec<(String, String)>, Vec<Defect>) {
    let mut out = Vec::new();
    let mut read = Vec::new();
    // The empty member belongs to the field: `a=1,,,b=2` is one hole the
    // sender left however many commas it ran together, and the sentence names
    // no member because there is no member to name.
    let mut saw_an_empty_member = false;
    for (member, head) in members {
        let (member, head) = (member.trim(), head.trim());
        if member.is_empty() {
            saw_an_empty_member = true;
            continue;
        }
        let Some(eq) = head.find('=') else {
            // A member that opens on its first `;` has written parameters and
            // no key, which is the key's defect and not a missing `=`.
            let def = if head.is_empty() {
                empty_algorithm
            } else {
                missing_eq
            };
            out.push(Defect::named(def.def, def.message.replace("{}", member)));
            continue;
        };
        let algorithm = head[..eq].trim();
        if algorithm.is_empty() {
            out.push(Defect::named(
                empty_algorithm.def,
                empty_algorithm.message.replace("{}", member),
            ));
            continue;
        }
        read.push((algorithm.to_string(), head[eq + 1..].trim().to_string()));
    }
    if saw_an_empty_member {
        out.push(Defect::named(
            empty_member.def,
            empty_member.message.to_string(),
        ));
    }
    (read, out)
}

/// RFC 3230's members: the text between two commas, whole.
fn legacy_members(value: &str) -> Vec<(&str, &str)> {
    value.split(',').map(|member| (member, member)).collect()
}

/// RFC 9530's members, read the way RFC 9651 reads a Dictionary: cut at the
/// commas outside a String or an Inner List, and each cut again before its
/// first `;` outside one, since what follows is the member's parameters and
/// not its value.
///
/// **A field that defines no parameter still receives them.** § 3.2 gives every
/// Dictionary member a `parameters` slot, § 2.3 makes that slot the extension
/// point every Item carries and discourages a field from treating an
/// unrecognized parameter as an error, and RFC 9530 defines none and refuses
/// none. So `sha-256=:…:;x=1` is a digest and a parameter, and a comma inside a
/// parameter's String ends no member. Reading the member's rest as its value
/// reported the first as "not a byte sequence" and the second as a member named
/// after the String's tail.
///
/// The parameters are judged here and nowhere else — `structured_headers_valid`
/// leaves the digest fields to this rule — and by the shared § 4.2.3.2 reader,
/// under the entry every Structured Field answers a parameter with.
///
// cite(RFC 9651 § 3.2): "the values are Items (Section 3.3) or arrays of Items, both of which can be Parameterized (Section 3.1.2)."
// cite(RFC 9651 § 2.3): "To preserve forward compatibility, field specifications are discouraged from defining the presence of an unrecognized parameter as an error condition."
fn dictionary_members<'a>(value: &'a str, out: &mut Vec<Defect>) -> Vec<(&'a str, &'a str)> {
    use crate::helpers::structured_fields::{
        parse_parameters, split_commas_outside_quotes, split_semicolons_outside_quotes,
    };
    split_commas_outside_quotes(value)
        .into_iter()
        .map(|member| {
            let parts = split_semicolons_outside_quotes(member);
            if let Some(defect) = parse_parameters(&parts[1..]) {
                out.push(Defect::named(
                    structured_field_defect(defect.kind),
                    format!("{} on member '{}'", defect.message, member),
                ));
            }
            (member, parts[0])
        })
        .collect()
}

/// The RFC 3230 preference shape: an algorithm token, and an optional weight.
///
/// **The weight is the part a bare token list cannot see.** § 4.3.1 brackets
/// `";" "q" "=" qvalue` after each algorithm, and the section's own example is
/// `MD5;q=0.3, sha;q=1` — so a reader taking the member whole for the
/// algorithm reports the `;` as a character no `token` admits, and does it for
/// every weighted member a sender writes.
///
/// **The bracket is RFC 9110's `weight` under its older spelling**, which is
/// why the defects are the ones every field carrying a weight answers with:
/// RFC 3230 takes `qvalue` from RFC 2616, whose production is the one § 12.4.2
/// prints now, the same equivalence the algorithm's `token` rests on. What the
/// older spelling does *not* carry is § 12.4.2's single `"q="` literal. RFC
/// 2616's notation lets linear white space stand between any two words and
/// separators, and `";" "q" "=" qvalue` is four of them, so `sha ; q = 0.5`
/// derives and `weight_equals_whitespace_forbidden` is not an entry this field
/// can draw.
///
/// A member's checks are a chain — the weight is read only once the algorithm
/// is one — and the member boundary is not, as in the `Digest` walk below.
fn legacy_want_digest_defect(value: &str) -> Vec<Defect> {
    use crate::helpers::headers::trim_ows;
    let mut out = Vec::new();
    let mut saw_an_empty_member = false;
    for member in value.split(',') {
        let member = member.trim();
        if member.is_empty() {
            saw_an_empty_member = true;
            continue;
        }
        let mut segments = member.split(';');
        // `split` yields at least one segment, the empty one for an empty
        // string; the member was refused above for being empty, so this is the
        // text in front of the first `;`, or all of it.
        let algorithm = trim_ows(segments.next().unwrap_or_default());

        // `token = 1*tchar` derives no empty string, and a scan for an invalid
        // character finds none in one — so a member that begins at its `;` is
        // named by the floor, not the scan.
        // cite(RFC 3230 § 4.1.1): "digest-algorithm = token"
        if algorithm.is_empty() {
            out.push(Defect::named(
                &TOKEN_EMPTY,
                format!("Want-Digest member '{member}' has empty algorithm"),
            ));
            continue;
        }
        // The wording names the algorithm as well as the character, because
        // two algorithms in one list can fail on the same octet and a sentence
        // saying only which octet would arrive twice, word for word. Both are
        // rendered, since the character is most often one that prints as
        // nothing or as a space.
        if let Some(c) = crate::helpers::token::find_invalid_token_char(algorithm) {
            out.push(Defect::named(
                token_character(c),
                format!(
                    "Want-Digest algorithm '{}' contains invalid character: {}",
                    shown_in_finding(algorithm),
                    describe_char(c)
                ),
            ));
            continue;
        }

        // Everything after the algorithm is the weight or nothing: the
        // bracket holds one `";" "q" "=" qvalue` and no parameter list. So the
        // walk reports the first segment that is not that and ends the member,
        // since whatever follows is more of the one thing that did not derive.
        let mut weight_seen = false;
        for segment in segments {
            let segment = trim_ows(segment);
            // Not an empty parameter slot, because there are no parameter
            // slots: the `;` is the weight's first word, and the member stops
            // before writing the rest of it.
            if segment.is_empty() {
                out.push(Defect::named(
                    &WEIGHT_MISSING,
                    format!("Want-Digest member '{member}' has a ';' with no weight after it"),
                ));
                break;
            }
            let (name, qv) = match segment.split_once('=') {
                Some((name, qv)) => (trim_ows(name), Some(trim_ows(qv))),
                None => (segment, None),
            };
            // RFC 2616 § 2.1 makes quoted literal text case-insensitive unless
            // a production says otherwise, and this one does not.
            if !name.eq_ignore_ascii_case("q") {
                out.push(Defect::named(
                    &WEIGHT_MALFORMED,
                    format!(
                        "'{segment}' is not a weight, and a weight is the only thing a Want-Digest member may carry after its algorithm (member '{member}')"
                    ),
                ));
                break;
            }
            // The bracket is written once, so a second weight derives from
            // nothing — and a recipient reading the first and one reading the
            // last disagree about the preference. The message names the
            // section because the shared entry cannot.
            if weight_seen {
                out.push(Defect::named(
                    &WEIGHT_DUPLICATED,
                    format!(
                        "More than one weight in Want-Digest member '{member}': RFC 3230 §4.3.1 brackets one"
                    ),
                ));
                break;
            }
            weight_seen = true;
            let Some(qv) = qv else {
                out.push(Defect::named(
                    &WEIGHT_MALFORMED,
                    format!(
                        "'{name}' is not a weight in Want-Digest member '{member}': the weight writes \"=\" and a qvalue after the \"q\", and this member stops at the name"
                    ),
                ));
                break;
            };
            // cite(RFC 9110 § 12.4.2): "qvalue = ( "0" [ "." 0*3DIGIT ] ) / ( "1" [ "." 0*3("0") ] )"
            if !crate::helpers::qvalue::valid_qvalue(qv) {
                out.push(Defect::named(
                    &QVALUE_MALFORMED,
                    format!("Invalid qvalue '{qv}' in Want-Digest member '{member}'"),
                ));
                break;
            }
        }
    }
    if saw_an_empty_member {
        out.push(Defect::named(
            &DIGEST_MEMBER_EMPTY,
            "Want-Digest header contains empty member".to_string(),
        ));
    }
    out
}

/// The RFC 3230 shape: an ordinary token and bare base64, with no `:`
/// delimiters and no structured field anywhere in it.
fn legacy_digest_defect(value: &str) -> Vec<Defect> {
    let (members, mut out) = key_value_members(
        legacy_members(value),
        MemberDefect {
            def: &DIGEST_MEMBER_EMPTY,
            message: "Digest header contains empty member",
        },
        MemberDefect {
            def: &DIGEST_EQUALS_MISSING,
            message: "Digest member '{}' missing '=' separator",
        },
        // `digest-algorithm = token`, and `token = 1*tchar` derives no empty
        // string -- the same id every other reader of that production answers
        // with.
        MemberDefect {
            def: &TOKEN_EMPTY,
            message: "Digest member '{}' has empty algorithm",
        },
    );

    // One member is one algorithm and its digest, and what is wrong with it is
    // read as a chain: a value that is not base64 is only a question once
    // there is a value at all. What does NOT chain is the member boundary --
    // the sender wrote each member on its own terms and corrects each on its
    // own, so the walk carries on to the next.
    for (algorithm, encoded) in members {
        if encoded.is_empty() {
            out.push(Defect::named(
                &DIGEST_VALUE_EMPTY,
                format!("Digest member '{}' has empty value", algorithm),
            ));
            continue;
        }

        // The algorithm is a token. RFC 3230 also makes it case-insensitive,
        // which is why no lowercase rule is applied on this legacy path — the
        // opposite of the structured fields below.
        // cite(RFC 3230 § 4.1.1): "digest-algorithm = token"
        // cite(RFC 3230 § 4.1.1): "All digest-algorithm values are case-insensitive."
        if let Some(c) = crate::helpers::token::find_invalid_token_char(&algorithm) {
            out.push(Defect::named(
                token_character(c),
                format!(
                    "Digest algorithm '{}' contains invalid character: {}",
                    shown_in_finding(&algorithm),
                    describe_char(c)
                ),
            ));
            continue;
        }

        // Neither document restates a character of the encoding, so a value
        // that does not decode is the same defect wherever it was carried.
        if base64::engine::general_purpose::STANDARD
            .decode(&encoded)
            .is_err()
        {
            out.push(Defect::named(
                &BASE64_MALFORMED,
                format!(
                    "Digest value for algorithm '{}' is not valid base64",
                    algorithm
                ),
            ));
        }
    }
    out
}

/// The RFC 9530 shape: a Dictionary key and a Byte Sequence.
fn structured_digest_defect(value: &str) -> Vec<Defect> {
    let mut out = Vec::new();
    let (members, member_defects) = key_value_members(
        dictionary_members(value, &mut out),
        MemberDefect {
            def: &STRUCTURED_FIELD_MEMBER_EMPTY,
            message: "Digest field contains empty member",
        },
        // A bare key is not a member with no value: § 4.2.2 gives it the
        // Boolean true, so what is wrong is the type of the value this field
        // defines rather than a delimiter nobody wrote.
        MemberDefect {
            def: &DIGEST_VALUE_MALFORMED,
            message: "Digest member '{}' missing '=' separator, so its value is the Boolean true and not a byte sequence",
        },
        MemberDefect {
            def: &STRUCTURED_FIELD_KEY_MALFORMED,
            message: "Digest member '{}' has empty algorithm",
        },
    );
    out.extend(member_defects);

    // As above: a member's own checks are a chain, and the member boundary is
    // not one.
    for (algorithm, encoded) in members {
        // These are Dictionary *keys*, not RFC 3230 tokens: an SF key may not
        // contain uppercase. The distinction matters most on exactly the path a
        // deployment is likely to take — RFC 3230's `digest-algorithm = token`
        // is case-insensitive and its registry spells the algorithms `SHA-256`,
        // `MD5`, so carrying that spelling across to Content-Digest produces a
        // field no structured-field parser will accept. The `key` grammar
        // itself is owned by the structured-fields helper.
        // cite(RFC 9530 § 2): "key conveys the hashing algorithm (see Section 5) used to compute the digest;"
        if !crate::helpers::structured_fields::is_valid_sf_key(&algorithm) {
            out.push(Defect::named(
                &STRUCTURED_FIELD_KEY_MALFORMED,
                format!(
                    "Digest algorithm key '{}' is not a valid structured-field key (keys are lowercase: try '{}')",
                    algorithm,
                    algorithm.to_ascii_lowercase()
                ),
            ));
            continue;
        }

        // The `:`-delimited base64 form, whose grammar the structured-fields
        // helper owns (hand-rolling it here was a second transcription of the
        // same rule).
        // cite(RFC 9530 § 2): "value is a Byte Sequence (Section 3.3.5 of [STRUCTURED-FIELDS]) that conveys an encoded version of the byte output produced by the digest calculation."
        if !crate::helpers::structured_fields::is_byte_sequence(&encoded) {
            out.push(Defect::named(
                &DIGEST_VALUE_MALFORMED,
                format!(
                    "Digest member '{}={}' value must be a byte sequence like ':b64:'",
                    algorithm, encoded
                ),
            ));
            continue;
        }

        // Two deliberate strictnesses beyond the grammar, neither of which the
        // spec states, so neither is cited. (1) `::` is a well-formed Byte
        // Sequence carrying zero bytes, but a digest of nothing identifies no
        // content, so it is reported. (2) the decode below demands canonical
        // padding, while a structured-field parser synthesizes padding when it
        // is missing — so an unpadded-but-decodable value is reported here and
        // accepted there.
        let inner = &encoded[1..encoded.len() - 1];
        if inner.is_empty() {
            out.push(Defect::named(
                &DIGEST_VALUE_EMPTY,
                format!("Digest member '{}' has empty byte sequence", algorithm),
            ));
            continue;
        }
        if base64::engine::general_purpose::STANDARD
            .decode(inner)
            .is_err()
        {
            out.push(Defect::named(
                &BASE64_MALFORMED,
                format!(
                    "Digest value for algorithm '{}' is not valid base64",
                    algorithm
                ),
            ));
        }
    }
    out
}

/// The RFC 9530 preference shape: a Dictionary key and a weight.
fn want_preference_defect(value: &str) -> Vec<Defect> {
    let mut out = Vec::new();
    let (members, member_defects) = key_value_members(
        dictionary_members(value, &mut out),
        MemberDefect {
            def: &STRUCTURED_FIELD_MEMBER_EMPTY,
            message: "Want-* header contains empty member",
        },
        // The same Boolean true, measured against the type *this* field
        // defines: § 4 asks for an Integer.
        MemberDefect {
            def: &DIGEST_PREFERENCE_MALFORMED,
            message: "Want member '{}' missing '=' separator, so its value is the Boolean true and not an integer",
        },
        MemberDefect {
            def: &STRUCTURED_FIELD_KEY_MALFORMED,
            message: "Want member '{}' has empty algorithm",
        },
    );
    out.extend(member_defects);

    for (algorithm, weight) in members {
        // Same Dictionary-key rule as the digest fields above.
        if !crate::helpers::structured_fields::is_valid_sf_key(&algorithm) {
            out.push(Defect::named(
                &STRUCTURED_FIELD_KEY_MALFORMED,
                format!(
                    "Want-* algorithm key '{}' is not a valid structured-field key (keys are lowercase: try '{}')",
                    algorithm,
                    algorithm.to_ascii_lowercase()
                ),
            ));
            continue;
        }

        // The bound is the spec's own, not a chosen tolerance, and the type is
        // Integer, so no decimal point.
        // cite(RFC 9530 § 4): "value is an Integer (Section 3.3.1 of [STRUCTURED-FIELDS]) that conveys an ascending, relative, weighted preference. It must be in the range 0 to 10 inclusive."
        // The weight is named beside the algorithm it belongs to: two members
        // can carry the same bad weight, and a sentence quoting only the weight
        // would be one sentence written twice.
        let Ok(n) = weight.parse::<i64>() else {
            out.push(Defect::named(
                &DIGEST_PREFERENCE_MALFORMED,
                format!(
                    "Want-* weight '{}' for '{}' is not an integer",
                    weight, algorithm
                ),
            ));
            continue;
        };
        // The two halves of one sentence, and they fail at two levels: a value
        // deriving from no Integer stops a parser, and one deriving from an
        // Integer is refused by the range printed beside the type.
        if !(0..=10).contains(&n) {
            out.push(Defect::named(
                &DIGEST_PREFERENCE_INVALID,
                format!(
                    "Want-* weight '{}' for '{}' out of range 0..=10",
                    weight, algorithm
                ),
            ));
        }
    }
    out
}

impl RuleMeta for DigestHeaderSyntax {
    fn id(&self) -> &'static str {
        "digest_header_syntax"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn description(&self) -> &'static str {
        "RFC 9530 obsoletes RFC 3230 and defines modern Integrity fields: `Content-Digest` (for message content), `Repr-Digest` (for representation data) and their preference counterparts `Want-Content-Digest` / `Want-Repr-Digest`. This rule validates:\n\n- **Legacy** `Digest` (`alg=base64`) and `Want-Digest` (algorithms, each with an optional `;q=` weight) header syntax, and flags their use as obsoleted by RFC 9530.\n- **New** RFC 9530 Integrity fields (`Content-Digest`, `Repr-Digest`) must follow the structured dictionary syntax (e.g., `sha-256=:BASE64:`) with byte sequences that decode as valid Base64. A member's parameters are not part of its value: RFC 9530 defines none and RFC 9651 gives every member room for them, so `sha-256=:BASE64:;x=1` is read as the digest it carries, and only a parameter that is not one is reported.\n- **Integrity preference** fields (`Want-Content-Digest`, `Want-Repr-Digest`) use algorithm=weight pairs where weight is an integer in 0..=10.\n- **Obsolete field**: presence of `Content-MD5` is flagged. It was removed from HTTP by RFC 7231 (not by RFC 9530, which does not mention it); prefer `Content-Digest`.\n\nAlgorithm names in the RFC 9530 fields are structured-field Dictionary keys and so must be lowercase (`sha-256`, not the `SHA-256` spelling used by the obsolete `Digest` field, whose algorithm token is case-insensitive)."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            RFC_9530_2,
            RFC_9530_3,
            RFC_9530_4,
            RFC_3230_4_1_1,
            RFC_3230_4_3_1,
            RFC_7231_APPENDIX_B,
            RFC_9110_5_6_2,
            RFC_9651_4_2_3_3,
            RFC_9651_4_2_2,
            RFC_9651_3_2,
            RFC_9651_4_2_3_1,
            RFC_9651_2_3,
            RFC_4648_3_3,
            RFC_3230_4_2,
            RFC_9530,
            RFC_9110_12_4_2,
        ]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    /// **Each entry in `FIELDS` already names the side its field belongs to**,
    /// and a content or representation digest is written by the peer that
    /// enclosed the content it covers — so the `Side` that selects the field
    /// section is the same fork the answer takes.
    fn party(&self) -> crate::rules::RuleParty {
        crate::rules::RuleParty::PerSite
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "Content-Digest: sha-256=:YWJj:",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("— a parameter RFC 9530 never defined is read past, comma and all, as RFC 9651 § 2.3 asks"),
                snippet: "Content-Digest: sha-256=:YWJj:;note=\"a, b\"",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "Content-Digest: sha-256=dGVzdA==   # missing the required ':' byte sequence delimiters",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "Digest: SHA-256=not-base64!  # legacy Digest is obsoleted by RFC 9530 and will be reported",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— RFC 3230's own example: the field is obsolete, and a `;q=` weight after each algorithm is well formed"),
                snippet: "Want-Digest: MD5;q=0.3, sha;q=1",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("— `Content-MD5` was removed from HTTP, whatever its value"),
                snippet: "Content-MD5: Q2hlY2sgSW50ZWdyaXR5IQ==",
            },
        ]
    }
}

impl Rule for DigestHeaderSyntax {
    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        // Eleven fields, one loop. Each was written out as its own block —
        // read the lines, report the unreadable one, validate, report the
        // defect — and the eleven copies differed only in the field's name, the
        // side it is read on, and which of four syntaxes it follows. Those are
        // the three columns of [`FIELDS`].
        //
        // **The loop answers for every field it reads.** It used to return at
        // the first one that had anything to say, so a message carrying a
        // malformed `Content-Digest` and a malformed `Repr-Digest` reported one
        // of them — and eleven fields are eleven independent things a sender
        // wrote, not one verdict on the message.
        let mut out: Vec<Violation> = Vec::new();
        {
            for field in FIELDS {
                let headers = match field.side {
                    Side::Request => &tx.request.headers,
                    Side::Response => match tx.response.as_ref() {
                        Some(resp) => &resp.headers,
                        None => continue,
                    },
                };

                for line in headers.get_all(field.name).iter() {
                    // Read as octets. Two of these four fields are lists of
                    // `token`s and two are Structured Fields; every one of the
                    // productions stops inside visible US-ASCII, so an octet
                    // outside it belongs to whichever of them was being read --
                    // not to a verdict about the field's encoding, which is
                    // what refusing the value outright reported.
                    let value = crate::helpers::headers::field_line_as_written(line);
                    let value = value.as_str();

                    let defects = field.syntax.defects(value);
                    let value_is_readable = defects.is_empty();
                    for defect in defects {
                        let defect = defect.in_context(|message| {
                            format!(
                                "Invalid {} header in {}: {} ({})",
                                field.display, field.side, message, field.reference
                            )
                        });
                        out.push(
                            ctx.by(field.side.party())
                                .report_with(defect.def, defect.message),
                        );
                    }

                    // A well-formed obsolete field is still a finding: the field
                    // itself is gone, not merely discouraged. Which entry says so
                    // is the field's, because the two were retired by two
                    // documents for two reasons.
                    //
                    // It stays behind the value, and that is a chain on purpose.
                    // A sender writing a retired field whose value is also
                    // malformed has one thing to do about it — stop writing the
                    // field — and telling them to correct the value they are to
                    // stop sending is a second sentence about the same act.
                    if let Some(obsolete) = field.obsolete {
                        if value_is_readable {
                            out.push(
                                ctx.by(field.side.party())
                                    .report_with(obsolete.def, obsolete.message.into()),
                            );
                        }
                    }
                }
            }
        }
        out
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &DigestHeaderSyntax;

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn make_req_digest(value: &str) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[("digest", value)]);
        tx
    }

    fn make_resp_digest(value: &str) -> crate::http_transaction::HttpTransaction {
        crate::test_helpers::make_test_transaction_with_response(200, &[("digest", value)])
    }

    fn make_req_want_digest(value: &str) -> crate::http_transaction::HttpTransaction {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("want-digest", value)]);
        tx
    }

    /// The findings that belong to a production this rule borrows, and a sample
    /// of the ones that do not. The line the table draws is between the
    /// productions and the fields: RFC 3230's legacy algorithm is a `token`,
    /// RFC 9530's Dictionary key is RFC 9651's `key` — the spelling a
    /// deployment carries across from the older registry and the one no
    /// structured-field parser will read — and everything else is a statement
    /// one of the two documents makes about its own members.
    #[rstest]
    #[case::legacy_digest_algorithm("digest", "sha@1=YWJj", "token_character_forbidden")]
    #[case::legacy_want_digest_algorithm("want-digest", "sha@1", "token_character_forbidden")]
    #[case::legacy_empty_member("digest", "sha-256=YWJj,", "digest_member_empty")]
    #[case::legacy_no_equals("digest", "sha-256", "digest_equals_missing")]
    #[case::structured_key_case(
        "content-digest",
        "SHA-256=:YWJj:",
        "structured_field_key_malformed"
    )]
    #[case::want_key_case("want-content-digest", "SHA-256=5", "structured_field_key_malformed")]
    #[case::structured_not_a_byte_sequence(
        "content-digest",
        "sha-256=YWJj",
        "digest_value_malformed"
    )]
    #[case::structured_empty_byte_sequence("content-digest", "sha-256=::", "digest_value_empty")]
    #[case::legacy_empty_value("digest", "sha-256=", "digest_value_empty")]
    #[case::legacy_bad_base64("digest", "sha-256=!!!", "base64_malformed")]
    #[case::structured_bad_base64("content-digest", "sha-256=:YWJ:", "base64_malformed")]
    #[case::want_weight_not_an_integer(
        "want-content-digest",
        "sha-256=1.5",
        "digest_preference_malformed"
    )]
    #[case::want_weight_out_of_range(
        "want-content-digest",
        "sha-256=11",
        "digest_preference_invalid"
    )]
    #[case::structured_empty_member(
        "content-digest",
        "sha-256=:YWJj:,",
        "structured_field_member_empty"
    )]
    #[case::legacy_empty_algorithm("digest", "=YWJj", "token_empty")]
    #[case::structured_empty_key("content-digest", "=:YWJj:", "structured_field_key_malformed")]
    #[case::structured_bare_key("content-digest", "sha-256", "digest_value_malformed")]
    #[case::legacy_field_is_obsolete("digest", "sha-256=YWJj", "digest_field_obsolete")]
    #[case::content_md5_is_obsolete("content-md5", "YWJj", "content_md5_obsolete")]
    #[case::want_bare_key("want-content-digest", "sha-256", "digest_preference_malformed")]
    fn only_the_legacy_algorithm_is_a_borrowed_production(
        #[case] field: &str,
        #[case] value: &str,
        #[case] violation: &str,
    ) {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(field, value)]);
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: crate::test_helpers::make_headers_from_pairs(&[(field, value)]),
            body_length: None,
            body_interrupted: false,
            trailers: None,
        });
        let finding = crate::test_helpers::run_rule(
            &DigestHeaderSyntax,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&["digest_header_syntax"]),
        )
        .unwrap_or_else(|| panic!("expected a finding for {field}: {value}"));
        assert_eq!(finding.violation, violation, "{field}: {value}");
    }

    #[rstest]
    #[case("SHA-256", true)]
    #[case("SHA-256, SHA-512", true)]
    #[case("sha-256", true)]
    #[case("sha@1", true)]
    #[case("", true)]
    #[case("SHA-256,", true)]
    fn request_want_digest_cases(#[case] value: &str, #[case] expect_violation: bool) {
        let rule = DigestHeaderSyntax;
        let tx = make_req_want_digest(value);
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["digest_header_syntax"]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(v.is_some(), "expected violation for '{}'", value);
        } else {
            assert!(v.is_none(), "did not expect violation for '{}'", value);
        }
    }

    /// The count the rule's doc states, read from the list it describes: a
    /// sentence counting entries is a census, and a census nothing checks was
    /// sixteen over a list of fourteen here for as long as it was written.
    #[test]
    fn the_census_above_is_the_declared_list() {
        let own = DECLARED
            .iter()
            .filter(|d| d.id.starts_with("digest_") || d.id.starts_with("content_md5_"))
            .count();
        assert_eq!((DECLARED.len() - own, own), (11, 8));
    }

    /// An algorithm refused for a character is named with the character
    /// rendered, in both generations' `token` readers: a NBSP octet printed as
    /// itself reads as a space, and the finding exists to point at it.
    /// A digest Dictionary member's parameters are not its value. RFC 9530
    /// defines none, RFC 9651 § 3.2 gives every member room for them, so a
    /// parameter RFC 9530 never named leaves the member the digest it was — a
    /// comma inside its String included — and only a parameter that is not one
    /// is reported, under the entry every Structured Field answers it with.
    /// RFC 3230's `Digest` has no parameters, so there the same text is not
    /// base64. Every finding, not the first.
    #[rstest]
    #[case::a_token_parameter("content-digest", "sha-256=:YWJj:;x=1", &[])]
    #[case::a_comma_in_a_parameter_string(
        "content-digest",
        r#"sha-256=:YWJj:;x="a, sha-512""#,
        &[]
    )]
    #[case::a_parameter_then_a_member("repr-digest", "sha-256=:YWJj:;x=?1, sha-512=:YWJj:", &[])]
    #[case::a_parameter_on_a_weight("want-content-digest", "sha-256=10;x=1, sha-512=3", &[])]
    #[case::a_parameter_on_a_bare_key(
        "content-digest",
        "sha-256;x=1",
        &["digest_value_malformed"]
    )]
    #[case::a_separator_alone("content-digest", "sha-256=:YWJj:;", &["structured_field_member_empty"])]
    #[case::a_parameter_key_in_upper_case(
        "repr-digest",
        "sha-256=:YWJj:;X=1",
        &["structured_field_key_malformed"]
    )]
    #[case::a_parameter_value_no_item_derives(
        "want-repr-digest",
        "sha-256=3;x=@",
        &["structured_field_value_malformed"]
    )]
    #[case::parameters_and_no_key(
        "content-digest",
        ";x=1, sha-256=:YWJj:",
        &["structured_field_key_malformed"]
    )]
    #[case::the_legacy_field_has_no_parameters(
        "digest",
        "sha-256=YWJj;x=1",
        &["base64_malformed"]
    )]
    fn a_dictionary_members_parameters_are_not_its_value(
        #[case] field: &str,
        #[case] value: &str,
        #[case] expected: &[&str],
    ) {
        let found: Vec<String> = crate::test_helpers::run_rule_all(
            &DigestHeaderSyntax,
            &crate::test_helpers::make_test_transaction_with_response(200, &[(field, value)]),
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&["digest_header_syntax"]),
        )
        .into_iter()
        .map(|v| v.violation)
        .collect();
        assert_eq!(found, expected, "{field}: {value}");
    }

    #[rstest]
    #[case::want_digest("want-digest", b"sha\xa01;q=0.5")]
    #[case::digest("digest", b"sha\xa01=YWJj")]
    fn a_refused_algorithm_names_its_octet(#[case] field: &str, #[case] value: &[u8]) {
        let mut tx = crate::test_helpers::make_test_transaction();
        let mut headers = crate::test_helpers::make_headers_from_pairs(&[]);
        headers.append(
            hyper::header::HeaderName::from_bytes(field.as_bytes()).expect("a field name"),
            hyper::header::HeaderValue::from_bytes(value).expect("obs-text is a legal field octet"),
        );
        tx.request.headers = headers;
        let found = crate::test_helpers::run_rule_all(
            &DigestHeaderSyntax,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&["digest_header_syntax"]),
        );
        assert_eq!(found.len(), 1, "{field}: {found:?}");
        assert_eq!(found[0].violation, "token_character_forbidden");
        assert!(
            found[0]
                .message
                .contains("'sha\\u{a0}1' contains invalid character: 0xA0"),
            "{}",
            found[0].message
        );
    }

    /// RFC 3230 § 4.3.1's member is `digest-algorithm [ ";" "q" "=" qvalue ]`,
    /// so what follows the `;` is read as a weight. The section's own example,
    /// and the same weight spaced out under RFC 2616's implied LWS, are values
    /// that read and earn the obsolescence and nothing else; each way the
    /// bracket fails to derive is its own id — never the algorithm's `token`
    /// entries, which is what a reader taking the `;` for part of the algorithm
    /// answered every weighted member with. Every finding, not the first, so a
    /// row cannot pass with a second id riding behind the one it names.
    #[rstest]
    #[case::the_sections_own_example("MD5;q=0.3, sha;q=1", &["digest_field_obsolete"])]
    #[case::spaced_under_implied_lws("sha-256 ; q = 0.5", &["digest_field_obsolete"])]
    #[case::upper_case_q("sha-256;Q=1.000", &["digest_field_obsolete"])]
    #[case::zero_weight("contentMD5;q=0", &["digest_field_obsolete"])]
    #[case::qvalue_out_of_range("sha-256;q=11", &["qvalue_malformed"])]
    #[case::qvalue_not_a_number("sha-256;q=abc", &["qvalue_malformed"])]
    #[case::separator_alone("sha-256;", &["weight_missing"])]
    #[case::not_the_weight("sha-256;charset=utf-8", &["weight_malformed"])]
    #[case::q_without_equals("sha-256;q", &["weight_malformed"])]
    #[case::two_weights("sha-256;q=0.5;q=0.8", &["weight_duplicated"])]
    #[case::weight_and_no_algorithm(";q=0.5", &["token_empty"])]
    #[case::bad_algorithm_before_a_weight("sha@1;q=0.5", &["token_character_forbidden"])]
    #[case::each_member_on_its_own("sha;q=2, md5;", &["qvalue_malformed", "weight_missing"])]
    fn want_digest_members_carry_a_weight(#[case] value: &str, #[case] expected: &[&str]) {
        let found: Vec<String> = crate::test_helpers::run_rule_all(
            &DigestHeaderSyntax,
            &make_req_want_digest(value),
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&["digest_header_syntax"]),
        )
        .into_iter()
        .map(|v| v.violation)
        .collect();
        assert_eq!(found, expected, "{value}");
    }

    #[test]
    fn non_utf8_request_want_digest_is_violation() -> anyhow::Result<()> {
        let rule = DigestHeaderSyntax;
        let mut tx = crate::test_helpers::make_test_transaction();
        use hyper::header::HeaderValue;
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        let bad = HeaderValue::from_bytes(&[0xff])?;
        hm.append("want-digest", bad);
        tx.request.headers = hm;
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["digest_header_syntax"]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn want_digest_empty_member_is_violation() {
        let rule = DigestHeaderSyntax;
        let tx = make_req_want_digest("sha-256=, , sha-512");
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["digest_header_syntax"]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn want_digest_deprecation_is_reported() {
        let rule = DigestHeaderSyntax;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("want-digest", "SHA-256")]);
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["digest_header_syntax"]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("obsoleted") || msg.contains("prefer Want-Content-Digest"));
    }

    #[test]
    fn multiple_want_digest_header_fields_are_checked() {
        let rule = DigestHeaderSyntax;
        let mut tx = crate::test_helpers::make_test_transaction();
        use hyper::header::HeaderValue;
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        hm.append("want-digest", HeaderValue::from_static("SHA-256"));
        hm.append("want-digest", HeaderValue::from_static("sha-256"));
        tx.request.headers = hm;
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["digest_header_syntax"]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "digest_header_syntax");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }

    #[rstest]
    #[case("SHA-256=YWJj", true)] // 'abc' -> YWJj
    #[case("SHA-256=YWJj, SHA-512=ZGVm", true)] // two members
    #[case("sha-256=YWJj", true)] // algorithm case is allowed as token (not enforced)
    #[case("SHA-256=not-base64!", true)]
    #[case("=YWJj", true)]
    #[case("SHA256", true)]
    #[case("", true)]
    #[case("SHA-256=", true)]
    #[case("SHA-256=Y WJj", true)]
    fn request_digest_cases(#[case] value: &str, #[case] expect_violation: bool) {
        let rule = DigestHeaderSyntax;
        let tx = make_req_digest(value);
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["digest_header_syntax"]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(v.is_some(), "expected violation for '{}'", value);
        } else {
            assert!(v.is_none(), "did not expect violation for '{}'", value);
        }
    }

    #[rstest]
    #[case("SHA-256=YWJj", true)]
    #[case("SHA-256=notbase64", true)]
    fn response_digest_cases(#[case] value: &str, #[case] expect_violation: bool) {
        let rule = DigestHeaderSyntax;
        let tx = make_resp_digest(value);
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["digest_header_syntax"]);

        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(v.is_some(), "expected violation for '{}'", value);
        } else {
            assert!(v.is_none(), "did not expect violation for '{}'", value);
        }
    }

    #[test]
    fn empty_header_absent_returns_none() {
        let rule = DigestHeaderSyntax;
        let tx = crate::test_helpers::make_test_transaction();
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["digest_header_syntax"]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn non_utf8_request_header_value_is_violation() -> anyhow::Result<()> {
        let rule = DigestHeaderSyntax;
        let mut tx = crate::test_helpers::make_test_transaction();
        use hyper::header::HeaderValue;
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        let bad = HeaderValue::from_bytes(&[0xff])?;
        hm.append("digest", bad);
        tx.request.headers = hm;
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["digest_header_syntax"]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn non_utf8_response_header_value_is_violation() -> anyhow::Result<()> {
        let rule = DigestHeaderSyntax;
        let mut tx = crate::test_helpers::make_test_transaction();
        use hyper::header::HeaderValue;
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        let bad = HeaderValue::from_bytes(&[0xff])?;
        hm.append("digest", bad);
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hm,
            body_length: None,
            body_interrupted: false,
            trailers: None,
        });
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["digest_header_syntax"]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn algorithm_invalid_token_char_is_violation() {
        let rule = DigestHeaderSyntax;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("digest", "SHA@1=YWJj")]);
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["digest_header_syntax"]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn legacy_digest_deprecation_is_reported() {
        let rule = DigestHeaderSyntax;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("digest", "SHA-256=YWJj")]);
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["digest_header_syntax"]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("obsoleted") || msg.contains("prefer Content-Digest"));
    }

    #[test]
    fn content_digest_structured_syntax_valid() {
        let rule = DigestHeaderSyntax;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-digest", "sha-256=:dGVzdA==:")],
        );
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["digest_header_syntax"]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn content_digest_structured_syntax_invalid_base64() {
        let rule = DigestHeaderSyntax;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-digest", "sha-256=:not-base64!:")],
        );
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["digest_header_syntax"]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn response_legacy_digest_deprecation_is_reported() {
        let rule = DigestHeaderSyntax;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("digest", "SHA-256=YWJj")],
        );
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["digest_header_syntax"]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("obsoleted") || msg.contains("prefer Content-Digest"));
    }

    #[test]
    fn content_digest_structured_syntax_invalid_base64_in_request() {
        let rule = DigestHeaderSyntax;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-digest",
            "sha-256=:not-base64!:",
        )]);
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["digest_header_syntax"]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("Invalid Content-Digest header") && msg.contains("RFC 9530"));
    }

    #[test]
    fn content_digest_trailing_comma_in_request_is_violation() {
        let rule = DigestHeaderSyntax;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "content-digest",
            "sha-256=:dGVzdA==:,",
        )]);
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["digest_header_syntax"]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn want_content_digest_valid_weights() {
        let rule = DigestHeaderSyntax;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("want-content-digest", "sha-512=3, sha-256=10")],
        );
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["digest_header_syntax"]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn want_content_digest_invalid_weight_is_violation() {
        let rule = DigestHeaderSyntax;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("want-content-digest", "sha-256=20")],
        );
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["digest_header_syntax"]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn want_content_digest_in_request_invalid_weight_is_violation() {
        let rule = DigestHeaderSyntax;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request
            .headers
            .append("want-content-digest", "sha-256=20".parse().unwrap());
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["digest_header_syntax"]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn content_md5_deprecation_is_reported() {
        let rule = DigestHeaderSyntax;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-md5", "dGVzdA==")],
        );
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["digest_header_syntax"]);
        // Add a simple check that presence of header yields a violation via our rule: we will add handling next
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn repr_digest_structured_syntax_valid() {
        let rule = DigestHeaderSyntax;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("repr-digest", "sha-256=:dGVzdA==:")],
        );
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["digest_header_syntax"]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn repr_digest_structured_syntax_invalid_base64() {
        let rule = DigestHeaderSyntax;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("repr-digest", "sha-256=:not-base64!:")],
        );
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["digest_header_syntax"]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn repr_digest_structured_syntax_invalid_base64_in_request() {
        let rule = DigestHeaderSyntax;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "repr-digest",
            "sha-256=:not-base64!:",
        )]);
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["digest_header_syntax"]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn want_repr_digest_valid_weights() {
        let rule = DigestHeaderSyntax;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("want-repr-digest", "sha-512=0, sha-256=10")],
        );
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["digest_header_syntax"]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn want_repr_digest_invalid_weight_is_violation() {
        let rule = DigestHeaderSyntax;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("want-repr-digest", "sha-256=20")],
        );
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["digest_header_syntax"]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn content_digest_non_utf8_is_violation() -> anyhow::Result<()> {
        let rule = DigestHeaderSyntax;
        let mut tx = crate::test_helpers::make_test_transaction();
        use hyper::header::HeaderValue;
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        let bad = HeaderValue::from_bytes(&[0xff])?;
        hm.append("content-digest", bad);
        tx.request.headers = hm;
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["digest_header_syntax"]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn content_digest_multiple_fields_are_checked() {
        let rule = DigestHeaderSyntax;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        use hyper::header::HeaderValue;
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        hm.append(
            "content-digest",
            HeaderValue::from_static("sha-256=:dGVzdA==:"),
        );
        hm.append(
            "content-digest",
            HeaderValue::from_static("sha-256=:not-base64!:"),
        );
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hm,

            body_length: None,
            body_interrupted: false,
            trailers: None,
        });
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["digest_header_syntax"]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn want_content_digest_non_integer_is_violation() {
        let rule = DigestHeaderSyntax;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("want-content-digest", "sha-256=abc")],
        );
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["digest_header_syntax"]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn repr_digest_request_non_utf8_is_violation() -> anyhow::Result<()> {
        let rule = DigestHeaderSyntax;
        let mut tx = crate::test_helpers::make_test_transaction();
        use hyper::header::HeaderValue;
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        let bad = HeaderValue::from_bytes(&[0xff])?;
        hm.append("repr-digest", bad);
        tx.request.headers = hm;
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["digest_header_syntax"]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn repr_digest_response_non_utf8_is_violation() -> anyhow::Result<()> {
        let rule = DigestHeaderSyntax;
        let mut tx = crate::test_helpers::make_test_transaction();
        use hyper::header::HeaderValue;
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        let bad = HeaderValue::from_bytes(&[0xff])?;
        hm.append("repr-digest", bad);
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hm,

            body_length: None,
            body_interrupted: false,
            trailers: None,
        });
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["digest_header_syntax"]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn content_digest_response_non_utf8_is_violation() -> anyhow::Result<()> {
        let rule = DigestHeaderSyntax;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        use hyper::header::HeaderValue;
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        let bad = HeaderValue::from_bytes(&[0xff])?;
        hm.append("content-digest", bad);
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hm,

            body_length: None,
            body_interrupted: false,
            trailers: None,
        });
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["digest_header_syntax"]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn want_content_digest_missing_equals_is_violation() {
        let rule = DigestHeaderSyntax;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("want-content-digest", "sha-256")],
        );
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["digest_header_syntax"]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn multiple_digest_header_fields_are_checked() {
        let rule = DigestHeaderSyntax;
        let mut tx = crate::test_helpers::make_test_transaction();
        // Construct headers with two digest fields: one valid, one invalid
        use hyper::header::HeaderValue;
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        hm.append("digest", HeaderValue::from_static("SHA-256=YWJj"));
        hm.append("digest", HeaderValue::from_static("SHA-256=not-base64!"));
        tx.request.headers = hm;
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["digest_header_syntax"]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    // Parametrized tests for structured digest fields (Content-Digest & Repr-Digest)
    #[rstest]
    #[case("content-digest", "sha-256=:dGVzdA==:", false)]
    #[case("content-digest", "sha-256=:not-base64!:", true)]
    #[case("content-digest", "sha-256=dGVzdA==", true)] // missing byte sequence colons
    #[case("content-digest", "sha-256=:", true)] // empty inner
    #[case("content-digest", "= :dGVzdA==:", true)] // missing alg
    #[case("content-digest", "sha@1=:dGVzdA==:", true)] // invalid alg token char
    #[case("repr-digest", "sha-256=:dGVzdA==:", false)]
    #[case("repr-digest", "sha-256=:not-base64!:", true)]
    // Dictionary keys are lowercase-only. `SHA-256` is how RFC 3230's registry
    // spells it, so this is the spelling a migration from `Digest` carries over —
    // and it makes the field unparseable as a structured field.
    #[case("content-digest", "SHA-256=:dGVzdA==:", true)]
    #[case("repr-digest", "SHA-512=:dGVzdA==:", true)]
    #[case("content-digest", "sha-256=:dGVzdA==:, SHA-512=:dGVzdA==:", true)]
    // `+` is a valid token character but not a valid SF key character.
    #[case("content-digest", "sha+256=:dGVzdA==:", true)]
    fn structured_digest_cases(
        #[case] header: &str,
        #[case] value: &str,
        #[case] expect_violation: bool,
    ) {
        let rule = DigestHeaderSyntax;
        let tx = crate::test_helpers::make_test_transaction_with_response(200, &[(header, value)]);
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["digest_header_syntax"]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(
                v.is_some(),
                "expected violation for '{}: {}'",
                header,
                value
            );
        } else {
            assert!(
                v.is_none(),
                "did not expect violation for '{}: {}'",
                header,
                value
            );
        }
    }

    /// The lowercase rule belongs to the structured fields only. RFC 3230's
    /// `digest-algorithm = token` is explicitly case-insensitive, so an uppercase
    /// algorithm in the legacy header is *not* a syntax error — the rule reports
    /// only the obsolescence. This guards against over-applying the fix.
    #[rstest]
    #[case("SHA-256=dGVzdA==")]
    #[case("MD5=dGVzdA==")]
    fn legacy_digest_algorithm_stays_case_insensitive(#[case] value: &str) {
        let rule = DigestHeaderSyntax;
        let tx = make_req_digest(value);
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["digest_header_syntax"]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .expect("legacy Digest is always reported as obsolete");
        assert!(
            v.message.contains("obsoleted by RFC 9530"),
            "expected the obsolescence report, not a syntax error: {}",
            v.message
        );
        assert!(!v.message.contains("structured-field key"));
    }

    #[rstest]
    #[case("want-content-digest", "SHA-256=5")]
    #[case("want-repr-digest", "SHA-512=3, sha-256=10")]
    fn want_field_keys_must_be_lowercase(#[case] header: &str, #[case] value: &str) {
        let rule = DigestHeaderSyntax;
        let tx = crate::test_helpers::make_test_transaction_with_response(200, &[(header, value)]);
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["digest_header_syntax"]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        )
        .unwrap_or_else(|| panic!("expected violation for '{}: {}'", header, value));
        assert!(v.message.contains("structured-field key"));
    }

    // Non-UTF8 tests for structured digest and want headers
    #[test]
    fn content_digest_non_utf8_in_request_is_violation() -> anyhow::Result<()> {
        let rule = DigestHeaderSyntax;
        let mut tx = crate::test_helpers::make_test_transaction();
        use hyper::header::HeaderValue;
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        let bad = HeaderValue::from_bytes(&[0xff])?;
        hm.append("content-digest", bad);
        tx.request.headers = hm;
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["digest_header_syntax"]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn want_content_digest_response_non_utf8_is_violation() -> anyhow::Result<()> {
        let rule = DigestHeaderSyntax;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        use hyper::header::HeaderValue;
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        let bad = HeaderValue::from_bytes(&[0xff])?;
        hm.append("want-content-digest", bad);
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hm,

            body_length: None,
            body_interrupted: false,
            trailers: None,
        });
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["digest_header_syntax"]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn want_repr_digest_response_non_utf8_is_violation() -> anyhow::Result<()> {
        let rule = DigestHeaderSyntax;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        use hyper::header::HeaderValue;
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        let bad = HeaderValue::from_bytes(&[0xff])?;
        hm.append("want-repr-digest", bad);
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hm,

            body_length: None,
            body_interrupted: false,
            trailers: None,
        });
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["digest_header_syntax"]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn want_field_response_missing_equals_is_violation() {
        let rule = DigestHeaderSyntax;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("want-repr-digest", "sha-256")],
        );
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["digest_header_syntax"]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    // Non-UTF8 request tests for Want-* headers (parametrized)
    #[rstest]
    #[case("want-content-digest")]
    #[case("want-repr-digest")]
    fn want_field_request_non_utf8_is_violation(
        #[case] header: &'static str,
    ) -> anyhow::Result<()> {
        let rule = DigestHeaderSyntax;
        let mut tx = crate::test_helpers::make_test_transaction();
        use hyper::header::HeaderValue;
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        let bad = HeaderValue::from_bytes(&[0xff])?;
        hm.append(header, bad);
        tx.request.headers = hm;
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["digest_header_syntax"]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        Ok(())
    }

    // Parametrized tests for Want-* weights and invalid forms
    #[rstest]
    #[case("want-content-digest", "sha-512=3, sha-256=10", false)]
    #[case("want-content-digest", "sha-256=20", true)]
    #[case("want-content-digest", "sha-256=-1", true)]
    #[case("want-content-digest", "sha-256=abc", true)]
    #[case("want-content-digest", "sha@1=5", true)]
    #[case("want-repr-digest", "sha-512=0, sha-256=10", false)]
    #[case("want-repr-digest", "sha-256=11", true)]
    fn want_field_cases(#[case] header: &str, #[case] value: &str, #[case] expect_violation: bool) {
        let rule = DigestHeaderSyntax;
        let tx = crate::test_helpers::make_test_transaction_with_response(200, &[(header, value)]);
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["digest_header_syntax"]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(
                v.is_some(),
                "expected violation for '{}: {}'",
                header,
                value
            );
        } else {
            assert!(
                v.is_none(),
                "did not expect violation for '{}: {}'",
                header,
                value
            );
        }
    }

    // Content-MD5 detection tests for both request and response
    #[test]
    fn content_md5_request_deprecation_is_reported() {
        let rule = DigestHeaderSyntax;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("content-md5", "dGVzdA==")]);
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["digest_header_syntax"]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn content_md5_non_utf8_is_violation_in_request() -> anyhow::Result<()> {
        let rule = DigestHeaderSyntax;
        let mut tx = crate::test_helpers::make_test_transaction();
        use hyper::header::HeaderValue;
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        let bad = HeaderValue::from_bytes(&[0xff])?;
        hm.append("content-md5", bad);
        tx.request.headers = hm;
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["digest_header_syntax"]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn content_md5_response_non_utf8_is_violation() -> anyhow::Result<()> {
        let rule = DigestHeaderSyntax;
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        use hyper::header::HeaderValue;
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        let bad = HeaderValue::from_bytes(&[0xff])?;
        hm.append("content-md5", bad);
        tx.response.as_mut().unwrap().headers = hm;

        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["digest_header_syntax"]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        Ok(())
    }

    // Combined header scenario: Digest (legacy) with Content-Digest — Digest should be reported first
    #[test]
    fn digest_and_content_digest_combined_reports_digest_deprecation() {
        let rule = DigestHeaderSyntax;
        let mut tx = crate::test_helpers::make_test_transaction();
        use hyper::header::HeaderValue;
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        hm.append("digest", HeaderValue::from_static("SHA-256=YWJj"));
        hm.append(
            "content-digest",
            HeaderValue::from_static("sha-256=:dGVzdA==:"),
        );
        tx.request.headers = hm;
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["digest_header_syntax"]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        // Since legacy Digest is checked first, we expect a violation about Digest being obsoleted
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("obsoleted") || msg.contains("prefer Content-Digest"));
    }

    // Edge-case tests: empty members, missing '=' in structured fields, trailing commas, and content-md5 response
    #[test]
    fn legacy_digest_empty_member_is_violation() {
        let rule = DigestHeaderSyntax;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "digest",
            "SHA-256=YWJj,,SHA-512=ZGVm",
        )]);
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["digest_header_syntax"]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[rstest]
    #[case("content-digest", "sha-256:dGVzdA==:", true)] // missing '=' separator
    #[case("repr-digest", "sha-256:dGVzdA==:", true)]
    #[case("content-digest", "sha-256=:dGVzdA==:,", true)] // trailing comma -> empty member
    fn structured_digest_missing_equals_or_empty(
        #[case] header: &str,
        #[case] value: &str,
        #[case] expect_violation: bool,
    ) {
        let rule = DigestHeaderSyntax;
        let tx = crate::test_helpers::make_test_transaction_with_response(200, &[(header, value)]);
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["digest_header_syntax"]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        if expect_violation {
            assert!(v.is_some());
        } else {
            assert!(v.is_none());
        }
    }

    #[test]
    fn content_digest_multiple_fields_in_request_are_checked() {
        let rule = DigestHeaderSyntax;
        let mut tx = crate::test_helpers::make_test_transaction();
        use hyper::header::HeaderValue;
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        hm.append(
            "content-digest",
            HeaderValue::from_static("sha-256=:dGVzdA==:"),
        );
        hm.append(
            "content-digest",
            HeaderValue::from_static("sha-256=:not-base64!:"),
        );
        tx.request.headers = hm;
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["digest_header_syntax"]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn legacy_digest_trailing_comma_is_empty_member_violation() {
        let rule = DigestHeaderSyntax;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("digest", "SHA-256=YWJj,")]);
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["digest_header_syntax"]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn header_name_case_insensitive_content_digest() {
        let rule = DigestHeaderSyntax;
        // Use mixed-case header name to test case-insensitivity
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_pairs(&[(
            "Content-Digest",
            "sha-256=:dGVzdA==:",
        )]);
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["digest_header_syntax"]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn content_digest_multiple_valid_fields_request_and_response_checked() {
        let rule = DigestHeaderSyntax;
        use hyper::header::HeaderValue;
        // Request: multiple valid content-digest fields
        let mut req = crate::test_helpers::make_test_transaction();
        let mut hm_req = crate::test_helpers::make_headers_from_pairs(&[]);
        hm_req.append(
            "content-digest",
            HeaderValue::from_static("sha-256=:dGVzdA==:"),
        );
        hm_req.append(
            "content-digest",
            HeaderValue::from_static("sha-512=:dGVzdA==:"),
        );
        req.request.headers = hm_req;
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["digest_header_syntax"]);
        let vreq = crate::test_helpers::run_rule(
            &rule,
            &req,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(vreq.is_none());

        // Response: multiple valid content-digest fields
        let mut resp_tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        let mut hm = crate::test_helpers::make_headers_from_pairs(&[]);
        hm.append(
            "content-digest",
            HeaderValue::from_static("sha-256=:dGVzdA==:"),
        );
        hm.append(
            "content-digest",
            HeaderValue::from_static("sha-512=:dGVzdA==:"),
        );
        resp_tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hm,

            body_length: None,
            body_interrupted: false,
            trailers: None,
        });
        let vresp = crate::test_helpers::run_rule(
            &rule,
            &resp_tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(vresp.is_none());
    }

    #[test]
    fn repr_digest_trims_spaces_and_is_valid() {
        let rule = DigestHeaderSyntax;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("repr-digest", " sha-256 = :dGVzdA==: ")],
        );
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["digest_header_syntax"]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_none());
    }

    #[test]
    fn want_field_space_around_equals_accepted_and_missing_equals_in_multi_is_violation() {
        let rule = DigestHeaderSyntax;
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["digest_header_syntax"]);

        // space around equals accepted
        let tx_ok = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("want-content-digest", "sha-512 = 2")],
        );
        let v_ok = crate::test_helpers::run_rule(
            &rule,
            &tx_ok,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v_ok.is_none());

        // missing equals in multi-members is a violation
        let tx_bad = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("want-content-digest", "sha-512=3, sha-256")],
        );
        let v_bad = crate::test_helpers::run_rule(
            &rule,
            &tx_bad,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v_bad.is_some());
        let msg = v_bad.unwrap().message;
        assert!(msg.contains("missing '=' separator") || msg.contains("not an integer"));
    }

    #[test]
    fn structured_digest_missing_equals_returns_meaningful_message() {
        let rule = DigestHeaderSyntax;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-digest", "sha-256:dGVzdA==:")],
        );
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["digest_header_syntax"]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("Invalid Content-Digest header") && msg.contains("RFC 9530"));
    }

    #[test]
    fn want_field_empty_member_is_violation() {
        let rule = DigestHeaderSyntax;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("want-content-digest", "sha-256=3, ,sha-512=5")],
        );
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["digest_header_syntax"]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn want_digest_invalid_char_reports_invalid_char_in_message() {
        let rule = DigestHeaderSyntax;
        let tx = make_req_want_digest("sha@1");
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["digest_header_syntax"]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("@") || msg.contains("invalid character"));
    }

    #[test]
    fn content_digest_empty_inner_reports_meaningful_message() {
        let rule = DigestHeaderSyntax;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-digest", "sha-256=:")],
        );
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["digest_header_syntax"]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        let msg = v.unwrap().message;
        let msg_lc = msg.to_lowercase();
        assert!(msg_lc.contains("empty") || msg_lc.contains("byte"));
    }

    #[test]
    fn want_field_invalid_alg_char_reports_char_in_message() {
        let rule = DigestHeaderSyntax;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("want-content-digest", "sha@1=5")],
        );
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["digest_header_syntax"]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
        let msg = v.unwrap().message;
        assert!(msg.contains("@") || msg.contains("invalid character"));
    }

    #[test]
    fn content_md5_response_deprecation_is_reported() {
        let rule = DigestHeaderSyntax;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[("content-md5", "dGVzdA==")],
        );
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["digest_header_syntax"]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    #[test]
    fn legacy_digest_trailing_comma_is_empty_member_violation_again() {
        let rule = DigestHeaderSyntax;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("digest", "SHA-256=YWJj,")]);
        let cfg =
            crate::test_helpers::make_test_config_with_enabled_rules(&["digest_header_syntax"]);
        let v = crate::test_helpers::run_rule(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(v.is_some());
    }

    /// Every member of one of these lists names an algorithm the sender chose
    /// and edits on its own, so a value defective twice states both. Each row
    /// drew exactly one finding before the walks collected.
    #[rstest]
    #[case::legacy_two_algorithms(
        "digest",
        "sha@1=YWJj,md 5=YWJj",
        &["token_character_forbidden", "token_whitespace_or_control_forbidden"]
    )]
    #[case::legacy_want_two_algorithms(
        "want-digest",
        "sha@1,md 5",
        &["token_character_forbidden", "token_whitespace_or_control_forbidden"]
    )]
    #[case::legacy_two_values(
        "digest",
        "sha-256=,md5=***",
        &["digest_value_empty", "base64_malformed"]
    )]
    #[case::structured_key_and_value(
        "content-digest",
        "SHA-256=:YWJj:, md5=abc",
        &["structured_field_key_malformed", "digest_value_malformed"]
    )]
    #[case::want_key_and_weight(
        "want-content-digest",
        "SHA-256=5, md5=99",
        &["structured_field_key_malformed", "digest_preference_invalid"]
    )]
    // Both defects here are raised inside the shared splitter, before any
    // caller's walk over the members it collected begins.
    #[case::split_missing_equals_and_empty_key(
        "content-digest",
        "sha-256, =:YWJj:",
        &["digest_value_malformed", "structured_field_key_malformed"]
    )]
    fn a_value_defective_twice_states_both(
        #[case] field: &str,
        #[case] value: &str,
        #[case] expected: &[&str],
    ) {
        let found = all_findings(field, value);
        let ids: Vec<&str> = found.iter().map(|v| v.violation.as_str()).collect();
        assert_eq!(
            ids,
            expected.to_vec(),
            "{:?}",
            found.iter().map(|v| &v.message).collect::<Vec<_>>()
        );
    }

    /// Two members failing the same way are still two members, and only the
    /// subject in the sentence tells them apart.
    #[rstest]
    #[case::legacy_algorithms("digest", "sha@1=YWJj,md@5=YWJj")]
    #[case::legacy_want_algorithms("want-digest", "sha@1,md@5")]
    #[case::structured_keys("content-digest", "SHA-256=:YWJj:, MD5=:YWJj:")]
    #[case::want_weights("want-content-digest", "sha-256=99, md5=99")]
    fn two_members_failing_alike_are_two_sentences(#[case] field: &str, #[case] value: &str) {
        let found = all_findings(field, value);
        assert_eq!(found.len(), 2, "{found:?}");
        assert_ne!(found[0].message, found[1].message, "{found:?}");
    }

    /// The empty member belongs to the field: however many commas a sender ran
    /// together, there is one hole to close and no member to name.
    #[rstest]
    #[case::legacy("digest", "sha-256=YWJj,,,md5=YWJj", "digest_member_empty")]
    #[case::legacy_want("want-digest", "sha-256,,,md5", "digest_member_empty")]
    #[case::structured(
        "content-digest",
        "sha-256=:YWJj:,,,md5=:YWJj:",
        "structured_field_member_empty"
    )]
    fn empty_members_are_one_finding_however_many(
        #[case] field: &str,
        #[case] value: &str,
        #[case] expected: &str,
    ) {
        let found = all_findings(field, value);
        let ids: Vec<&str> = found.iter().map(|v| v.violation.as_str()).collect();
        assert!(
            ids.iter().filter(|id| **id == expected).count() == 1,
            "{ids:?}"
        );
    }

    /// Eleven fields are eleven independent things a sender wrote. The loop
    /// returned at the first that had anything to say, so a message carrying
    /// two malformed digest fields reported one of them.
    #[test]
    fn two_defective_fields_on_one_message_are_two_findings() {
        let rule = DigestHeaderSyntax;
        let tx = crate::test_helpers::make_test_transaction_with_response(
            200,
            &[
                ("content-digest", "SHA-256=:YWJj:"),
                ("repr-digest", "MD5=:YWJj:"),
            ],
        );
        let found = crate::test_helpers::run_rule_all(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert_eq!(found.len(), 2, "{found:?}");
        assert!(
            found[0].message.contains("Content-Digest"),
            "{}",
            found[0].message
        );
        assert!(
            found[1].message.contains("Repr-Digest"),
            "{}",
            found[1].message
        );
    }

    /// A retired field whose value is also malformed gives a sender one thing
    /// to do about it, so the obsolescence stays behind the value.
    #[test]
    fn an_obsolete_field_with_a_malformed_value_says_only_what_is_malformed() {
        let found = all_findings("digest", "sha@1=YWJj");
        let ids: Vec<&str> = found.iter().map(|v| v.violation.as_str()).collect();
        assert_eq!(ids, vec!["token_character_forbidden"], "{found:?}");
    }

    /// Read one field's value on the side it is defined for, keeping every
    /// finding: `run_rule` takes the first of however many, which is exactly
    /// what a walk that has started answering twice would pass.
    fn all_findings(field: &str, value: &str) -> Vec<Violation> {
        let rule = DigestHeaderSyntax;
        let tx = match field {
            "want-digest" => {
                let mut tx = crate::test_helpers::make_test_transaction();
                tx.request.headers =
                    crate::test_helpers::make_headers_from_pairs(&[(field, value)]);
                tx
            }
            _ => crate::test_helpers::make_test_transaction_with_response(200, &[(field, value)]),
        };
        crate::test_helpers::run_rule_all(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
    }

    #[test]
    fn needs_no_response() {
        let rule = DigestHeaderSyntax;
        assert!(!rule.needs_response());
    }
}
