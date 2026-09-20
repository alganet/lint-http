// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::lint::Violation;
use crate::rules::{Rule, RuleMeta};
use crate::violations::cache_control::{
    CACHE_CONTROL_ARGUMENT_QUOTED_FORM_FORBIDDEN, CACHE_CONTROL_DIRECTIVE_ARGUMENT_FORBIDDEN,
    CACHE_CONTROL_DIRECTIVE_ARGUMENT_MISSING, CACHE_CONTROL_NO_CACHE_ARGUMENT_EMPTY,
    CACHE_CONTROL_PRIVATE_ARGUMENT_EMPTY, RFC_9111_5_2, RFC_9111_5_2_1_1, RFC_9111_5_2_1_2,
    RFC_9111_5_2_1_3, RFC_9111_5_2_1_4, RFC_9111_5_2_2_1, RFC_9111_5_2_2_10, RFC_9111_5_2_2_4,
    RFC_9111_5_2_2_7, RFC_9111_5_2_3,
};
use crate::violations::delta_seconds::{DELTA_SECONDS_CHARACTER_FORBIDDEN, RFC_9111_1_2_2};
use crate::violations::list::{cache_directive_member, LIST_MEMBER_EMPTY, RFC_9110_5_6_1_1};
use crate::violations::quoted_pair::QUOTED_PAIR_MALFORMED;
use crate::violations::quoted_string::{
    quoted_string_defect, QUOTED_STRING_CONTROL_CHARACTER_FORBIDDEN,
    QUOTED_STRING_DELIMITER_MISSING, QUOTED_STRING_QUOTE_ESCAPE_MISSING, RFC_9110_5_6_4,
};
use crate::violations::token::{
    token_character, RFC_9110_5_6_2, TOKEN_CHARACTER_FORBIDDEN, TOKEN_EMPTY,
    TOKEN_WHITESPACE_OR_CONTROL_FORBIDDEN,
};
use crate::violations::ViolationDef;

pub struct CacheControlDirectiveValid;

/// The eight defects `cache_control_token_valid` declares, declared here for a
/// second time and by a rule that reads a *different* question of the same
/// members — plus the one this rule reaches on its own.
///
/// § 1.2.1 is why the first eight transfer with nothing to decide: RFC 9111
/// imports `token`, `quoted-string` and `field-name` from RFC 9110 by reference
/// and takes the `#` list construct from § 5.6.1, so every production this rule
/// measures is one another field already reports through.
///
/// The ninth is the one this rule is *named* for and it is a production too,
/// which took a second reading to see. A `max-age` argument that is a
/// well-formed `token` and not a number breaks nothing about the
/// `cache-directive` — but § 5.2.2.1 gives that directive's argument the syntax
/// `delta-seconds`, so the name commits the value to a second production and
/// the value failed it.
///
/// The next two are the sentences with no production behind them at all: a
/// qualified directive whose argument lists no field, written once in
/// `no-cache`'s subsection and once in `private`'s. They are the
/// [`cache_control`](crate::violations::cache_control) subject — the layer above
/// this field's grammar, where a directive's own definition says what its
/// argument must say.
///
/// The next is that subject's third entry, and it is about the *form* of a
/// `delta-seconds` argument rather than its value: `max-age="60"` is the
/// `quoted-string` alternative the `cache-directive` grammar admits and the
/// directive's subsection tells a sender not to write. It used to report as
/// `token_character_forbidden` on the closing quote, which named a production
/// the value does not break.
///
/// The last two are the same subject asked one question earlier: not what the
/// argument says but whether the directive takes one. § 5.2 answers it for
/// every directive it defines — none does, unless the directive's own
/// subsection prints an argument syntax — and three of the subsections that do
/// then say what their directive means with the argument left off. So the
/// vocabulary is three-valued, and it is a fact about the document rather than
/// about the value: the same octets after `no-cache=` are conforming written by
/// an origin and a finding written by a client.
static DECLARED: &[&ViolationDef] = &[
    &LIST_MEMBER_EMPTY,
    &TOKEN_EMPTY,
    &TOKEN_CHARACTER_FORBIDDEN,
    &TOKEN_WHITESPACE_OR_CONTROL_FORBIDDEN,
    &QUOTED_STRING_DELIMITER_MISSING,
    &QUOTED_PAIR_MALFORMED,
    &QUOTED_STRING_QUOTE_ESCAPE_MISSING,
    &QUOTED_STRING_CONTROL_CHARACTER_FORBIDDEN,
    &DELTA_SECONDS_CHARACTER_FORBIDDEN,
    &CACHE_CONTROL_NO_CACHE_ARGUMENT_EMPTY,
    &CACHE_CONTROL_PRIVATE_ARGUMENT_EMPTY,
    &CACHE_CONTROL_ARGUMENT_QUOTED_FORM_FORBIDDEN,
    &CACHE_CONTROL_DIRECTIVE_ARGUMENT_MISSING,
    &CACHE_CONTROL_DIRECTIVE_ARGUMENT_FORBIDDEN,
];

/// The specification references this rule declares, each named so a finding
/// site can cite the one it enforces. `specifications()` below is built from
/// exactly these, so the docs and the citations cannot name different text.
const RFC_9111_1_2_1: crate::rules::SpecRef = crate::rules::SpecRef {
    spec: "RFC 9111",
    section: Some("1.2.1"),
    url: "https://www.rfc-editor.org/rfc/rfc9111.html#section-1.2.1",
    note: "Imported Rules — `token`, `quoted-string` and `field-name` are RFC 9110's, \
           taken by reference and not restated, which is why a directive's parts report \
           the same defects as any other field written out of them",
};

/// One finding from the reading, and the defect it reports as where the
/// catalogue names that defect.
///
/// The shape `expect_header_valid` settled — a judge that is half converted
/// says so in its type — is not this rule's any more: the sentence no
/// production carries got a subject of its own, one entry per directive that
/// writes it.
struct Defect {
    def: &'static ViolationDef,
    message: String,
}

impl Defect {
    /// A defect the catalogue names.
    fn named(def: &'static ViolationDef, message: String) -> Self {
        Self { def, message }
    }
}

impl CacheControlDirectiveValid {
    /// Every defect in one message's `Cache-Control` field.
    ///
    /// Read over the whole section and as octets. `Cache-Control =
    /// #cache-directive` makes the field lines of a section one list, and a
    /// directive name holding an octet outside visible US-ASCII is a `token`
    /// defect rather than a fact about the field's encoding — which is what
    /// reading line by line through the string reader made it. Where the
    /// members come from, and which of them the grammar's `#element` even
    /// admits, is [`crate::helpers::cache_control`]'s answer.
    ///
    /// **Each directive states its own argument syntax, so a response whose
    /// `max-age` carries letters and whose `private` names no field has two
    /// corrections to make and not one.** The walk used to end at the first,
    /// which on this field is the masking with the widest reach in the
    /// catalogue: most `Cache-Control` values name several directives.
    ///
    /// **The empty member is the list's defect and not a member's**, so it is
    /// stated once however many gaps the value carries — the same reading
    /// `cache_control_token_valid` makes of the same list beside this one.
    fn defect(
        &self,
        headers: &hyper::HeaderMap,
        side: &str,
        party: crate::lint::Party,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        let Some(value) =
            crate::helpers::headers::combined_field_value_as_written(headers, "cache-control")
        else {
            return Vec::new();
        };
        let mut out = Vec::new();
        let mut saw_an_empty_member = false;
        for member in crate::helpers::cache_control::members_of(&value) {
            if member.is_empty() {
                saw_an_empty_member = true;
                continue;
            }
            for defect in member_defect(member, side) {
                let message = format!(
                    "Invalid Cache-Control header in {}: {}",
                    side, defect.message
                );
                out.push(ctx.by(party).report_with(defect.def, message));
            }
        }
        if saw_an_empty_member {
            let empty = crate::helpers::cache_control::MemberDefect::Empty;
            out.push(ctx.by(party).report_with(
                cache_directive_member(empty),
                format!(
                    "Invalid Cache-Control header in {}: {}",
                    side,
                    empty.message()
                ),
            ));
        }
        out
    }
}

impl RuleMeta for CacheControlDirectiveValid {
    fn id(&self) -> &'static str {
        "cache_control_directive_valid"
    }

    fn config_example(&self) -> &'static str {
        r#"enabled = true
"#
    }

    fn description(&self) -> &'static str {
        "Validate `Cache-Control` directive names and argument formats for common correctness issues. This rule enforces directive-specific semantics such as:\n\n- `max-age`, `s-maxage`, `max-stale`, `min-fresh`, `stale-while-revalidate` and `stale-if-error` must have non-negative integer values (delta-seconds), and RFC 9111 has a sender write that argument in the token form: `max-age=\"60\"` is a well-formed `quoted-string` every recipient reads, and a form the directive's own section says a sender MUST NOT generate.\n- `private` and `no-cache` when carrying a field-name-list must provide a comma-separated list of field-names (tokens) either as an unquoted list or inside a quoted-string.\n- Unquoted directive values must follow the `token` grammar and quoted values must be valid `quoted-string`s.\n- A directive carries an argument only where its own subsection defines one. RFC 9111 § 5.2 allows none otherwise, so `no-store=1` is reported; and where a subsection defines an argument without saying what the bare directive means — `max-age`, `min-fresh`, `s-maxage` — the directive written alone is reported too. `max-stale`, and a response `no-cache` or `private`, each define their unqualified form and are conforming bare. Directives this document does not define state their arity elsewhere and are not judged.\n\nThis rule complements `cache_control_token_valid` which enforces general token/quoted-string syntax."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            RFC_9111_5_2,
            RFC_9111_1_2_1,
            RFC_9110_5_6_1_1,
            RFC_9110_5_6_2,
            RFC_9110_5_6_4,
            RFC_9111_1_2_2,
            RFC_9111_5_2_2_4,
            RFC_9111_5_2_2_7,
            RFC_9111_5_2_2_1,
            RFC_9111_5_2_1_1,
            RFC_9111_5_2_1_2,
            RFC_9111_5_2_1_3,
            RFC_9111_5_2_2_10,
            RFC_9111_5_2_1_4,
            RFC_9111_5_2_3,
        ]
    }

    fn violations(&self) -> &'static [&'static ViolationDef] {
        DECLARED
    }

    /// **Both halves send `Cache-Control`, and the directives are not the same
    /// vocabulary in each.** A request states what its sender will accept from a
    /// cache and a response states what may be done with it, so a malformed
    /// directive is the defect of whichever peer wrote the field — which is the
    /// same `side` this reader already words its finding with.
    fn party(&self) -> crate::rules::RuleParty {
        crate::rules::RuleParty::PerSite
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: None,
                snippet: "Cache-Control: max-age=3600\nCache-Control: s-maxage=0, public\nCache-Control: private=\"Set-Cookie, X-Foo\"\nCache-Control: private=Foo,bar",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "Cache-Control: max-age=abc     # non-numeric max-age\nCache-Control: max-age=-1      # negative values not allowed\nCache-Control: s-maxage=1.5    # fractional values invalid\nCache-Control: max-age=\"60\"    # the quoted-string form a sender must not generate\nCache-Control: private=Set Cookie  # space in token\nCache-Control: private=\"Set Cookie\" # quoted content contains space-separated token",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(a directive defined by its argument, written without one)"),
                snippet: "HTTP/1.1 200 OK\nCache-Control: public, max-age",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(an argument on a directive RFC 9111 § 5.2 allows none for)"),
                snippet: "HTTP/1.1 200 OK\nCache-Control: no-store=1",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(the three directives whose subsection defines their unqualified form)"),
                snippet: "HTTP/1.1 200 OK\nCache-Control: no-cache\nCache-Control: private\nCache-Control: max-age=0, must-revalidate",
            },
        ]
    }
}

impl Rule for CacheControlDirectiveValid {
    fn findings(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        ctx: &crate::rules::RuleContext<'_>,
    ) -> Vec<Violation> {
        // One finding per section. Both sides of the exchange carry this field
        // and are read the same way; only the word in the finding differs, and
        // a directive the client wrote is not evidence about the one the origin
        // sent back.
        // cite(RFC 9111 § 5.2): "The "Cache-Control" header field is used to list directives for caches along the request/response chain."
        let mut out = Vec::new();
        out.extend(self.defect(
            &tx.request.headers,
            "request",
            crate::lint::Party::Client,
            ctx,
        ));
        if let Some(resp) = &tx.response {
            out.extend(self.defect(&resp.headers, "response", crate::lint::Party::Server, ctx));
        }
        out
    }
}

/// What is wrong with one `cache-directive`, if anything.
///
/// The name is read by the shared strict reader, which owns the three defects
/// the two Cache-Control syntax rules report identically. What this rule adds is
/// the part that is its own: what each *named* directive's argument may say.
// cite(RFC 9111 § 5.2): "cache-directive = token [ "=" ( token / quoted-string ) ]"
fn member_defect(member: &str, side: &str) -> Vec<Defect> {
    let directive = match crate::helpers::cache_control::read_member(member) {
        Ok(directive) => directive,
        // The three defects the reader names are the list's and the token's,
        // and both rules reading this field now answer with the same ids for
        // them. Their *sentences* were already one, because the reader words
        // them; what could not be shared until now is which defect they are.
        Err(defect) => {
            return vec![Defect::named(
                cache_directive_member(defect),
                defect.message(),
            )]
        }
    };
    let name = directive.name;
    // **Whether the directive may carry an argument at all is asked before what
    // the argument says**, because it is the question an absent argument has an
    // answer to. `Directive::argument` distinguishes "no `=` was written"
    // (`None`) from "an `=` was written with nothing after it" (`Some("")`), and
    // one `Option::filter` used to send both down the same silent path: an
    // argument this rule could not measure and an argument the directive was
    // owed were indistinguishable from a directive read and found correct.
    if let Some(defect) = arity_defect(&directive, side) {
        return vec![defect];
    }

    // An empty argument is not read below, and it is not a silence: `foo=`
    // derives from no `cache-directive` whatever name is in front of it, and
    // the token rule beside this reports it as
    // `cache_control_directive_value_empty`. Nothing is left for this rule to
    // add — the value is empty however the directive would have used it, so
    // there is no form to compare it against — and reading it here as well
    // would draw one value twice. That is a statement about an argument that
    // was *written*, which is why the arity above is asked first and separately:
    // it is the only reading `Some("")` and `None` share an answer to, and they
    // share it because § 5.2 defines no directive with an empty argument.
    let Some(argument) = directive.argument.filter(|a| !a.is_empty()) else {
        return Vec::new();
    };

    match name.to_ascii_lowercase().as_str() {
        // Every directive whose subsection gives the argument the syntax
        // `delta-seconds`. The four RFC 9111 defines are read against their own
        // sentences below; the two RFC 5861 defines print `"=" delta-seconds`
        // and no other form, and that document is not in this crate's citation
        // store, so their digits are asked under the production alone.
        "max-age"
        | "s-maxage"
        | "max-stale"
        | "min-fresh"
        | "stale-while-revalidate"
        | "stale-if-error" => delta_seconds_defect(name, argument, side)
            .into_iter()
            .collect(),
        // **`private` on either side, `no-cache` only where the `#field-name`
        // argument is defined.** § 5.2.2.7 and § 5.2.2.4 are the two paragraphs
        // that define a qualified form, and only one of the two names is
        // defined twice: § 5.2.1.4's request `no-cache` gives it no argument at
        // all, so the arity reading above has already answered for that side and
        // asking the qualified form's sentence of it as well would report a
        // request against a paragraph about a response. `private` is defined
        // once, in § 5.2.2.7, and keeps that definition wherever it is written.
        "private" => field_name_list_defect(name, argument),
        "no-cache" if side != "request" => field_name_list_defect(name, argument),
        _ => {
            // For other directives, accept token or quoted-string and ensure token syntax if unquoted
            if argument.starts_with('"') {
                if let Err(defect) = crate::helpers::quoted_string::check_quoted_string(argument) {
                    return vec![Defect::named(
                        quoted_string_defect(defect),
                        format!(
                            "Invalid quoted-string in directive {} value: {}",
                            name,
                            defect.message(argument)
                        ),
                    )];
                }
                return Vec::new();
            }
            crate::helpers::token::find_invalid_token_char(argument)
                .map(|c| {
                    Defect::named(
                        token_character(c),
                        format!(
                            "Directive {} value contains invalid character: '{}'",
                            name, c
                        ),
                    )
                })
                .into_iter()
                .collect()
        }
    }
}

/// What RFC 9111 says about whether the directive in front of us takes an
/// argument, and the subsection that says it.
///
/// **Three answers, and § 5.2 writes the default for all of them in one
/// sentence**: no argument is defined, nor allowed, unless the directive's own
/// subsection says otherwise. The subsections that say otherwise print an
/// "Argument syntax" block, and three of those go on to define what the bare
/// form means — which is the difference between an argument that is owed and
/// one that is merely offered, and it is stated per directive rather than
/// derivable from anything.
///
/// **The side decides the answer for exactly one directive, and decides the
/// section for the four defined twice.** `no-cache` is two directives with one
/// spelling: § 5.2.2.4 gives the response one a `#field-name` and § 5.2.1.4
/// gives the request one nothing, so the same octets are conforming from an
/// origin and a finding from a client. `max-age`, `no-store` and `no-transform`
/// are also defined on both sides and each agrees with itself, so for them the
/// side picks only the paragraph an operator is sent to. **Every other
/// directive is defined once**, and a message carrying it on the other side is
/// still carrying that directive — § 5.2's sentence is about the directives the
/// document defines and not about which half of an exchange writes them — so
/// the arity holds and the section is the one place it is defined. Whether a
/// request directive belongs in a response at all is a different sentence and
/// no reading here makes it.
///
/// **Everything absent from this table is an extension directive and is not
/// judged.** § 5.2's sentence is scoped to the directives RFC 9111 defines, so
/// `immutable`, RFC 5861's pair and § 5.2.3's own `community="UCI"` state their
/// arity in documents this reading has not opened. The reader beside this one
/// asks RFC 5861's two for `delta-seconds` digits under the production alone,
/// for the same reason and with the same limit.
// cite(RFC 9111 § 5.2): "For the cache directives defined below, no argument is defined (nor allowed) unless stated otherwise."
// cite(RFC 9111 § 5.2.3): "When the directive requires an argument, what it means when it is missing"
// cite(RFC 9111 § 5.2.3): "When the directive does not take an argument, what it means when an argument is present"
fn arity(name: &str, side: &str) -> Option<Arity> {
    let request = side == "request";
    Some(match name.to_ascii_lowercase().as_str() {
        // An "Argument syntax" block and no sentence giving the bare form a
        // meaning: the argument is the whole of what the directive says.
        "max-age" if request => Arity::Required("5.2.1.1"),
        "max-age" => Arity::Required("5.2.2.1"),
        "min-fresh" => Arity::Required("5.2.1.3"),
        "s-maxage" => Arity::Required("5.2.2.10"),
        // An "Argument syntax" block, and the subsection then says what the
        // directive means without one. Nothing to report either way — except
        // that the REQUEST `no-cache` is a different directive with the same
        // name, defined in § 5.2.1.4 and given no argument at all.
        "max-stale" => Arity::Optional,
        "private" => Arity::Optional,
        "no-cache" if !request => Arity::Optional,
        "no-cache" => Arity::Forbidden("5.2.1.4"),
        // No "Argument syntax" block, so § 5.2's sentence is the whole of what
        // the document says about their arguments.
        "no-store" if request => Arity::Forbidden("5.2.1.5"),
        "no-store" => Arity::Forbidden("5.2.2.5"),
        "no-transform" if request => Arity::Forbidden("5.2.1.6"),
        "no-transform" => Arity::Forbidden("5.2.2.6"),
        "only-if-cached" => Arity::Forbidden("5.2.1.7"),
        "must-revalidate" => Arity::Forbidden("5.2.2.2"),
        "must-understand" => Arity::Forbidden("5.2.2.3"),
        "proxy-revalidate" => Arity::Forbidden("5.2.2.8"),
        "public" => Arity::Forbidden("5.2.2.9"),
        _ => return None,
    })
}

/// The three answers [`arity`] gives, each carrying the subsection an operator
/// is sent to — which is the directive's own, never § 5.2's, because the
/// paragraph that defines the directive is the one that says what it owes.
enum Arity {
    /// The subsection gives an argument syntax and no meaning without one.
    Required(&'static str),
    /// The subsection gives an argument syntax and a meaning without one.
    Optional,
    /// The subsection gives no argument syntax, so § 5.2's default stands.
    Forbidden(&'static str),
}

/// The directive's arity measured against what the sender actually wrote.
///
/// **`Some("")` is neither of the two things this asks about, and it is the one
/// value both arms decline.** A `max-age=` has not been given an argument, and a
/// `no-store=` has not been given one either — but that value derives from no
/// `cache-directive` at all, and the entry for the production the sender broke
/// already says so and is reported by the rule beside this one. So this reading
/// answers only for values the grammar admits: an argument written, or no `=`
/// written. Asking it of the empty form as well would draw one value twice for
/// one edit.
fn arity_defect(
    directive: &crate::helpers::cache_control::Directive<'_>,
    side: &str,
) -> Option<Defect> {
    let name = directive.name;
    match arity(name, side)? {
        Arity::Optional => None,
        Arity::Required(section) if directive.argument.is_none() => Some(Defect::named(
            &CACHE_CONTROL_DIRECTIVE_ARGUMENT_MISSING,
            format!(
                "{name} is written with no argument; RFC 9111 § {section} defines \
                 {name} by the argument it carries and gives the bare directive no meaning"
            ),
        )),
        Arity::Required(_) => None,
        Arity::Forbidden(section) => directive
            .argument
            .filter(|a| !a.is_empty())
            .map(|argument| {
                Defect::named(
                    &CACHE_CONTROL_DIRECTIVE_ARGUMENT_FORBIDDEN,
                    format!(
                        "{name}={argument} gives {name} an argument; RFC 9111 § {section} defines \
                     it with none, and § 5.2 allows none where none is defined, so a cache \
                     reads this as a plain {name}"
                    ),
                )
            }),
    }
}

/// The `#field-name` argument `private` and `no-cache` share, quoted or bare.
///
/// The two spellings ask the same question of each name, which is why the walk
/// below is written once over whichever list the argument turned out to be.
///
/// **Every part of this argument is borrowed and the argument syntax says so.**
/// `#field-name` is § 5.6.1's list construct around § 5.1's `field-name`, which
/// is a `token` — so a stray comma inside the argument is the same defect as a
/// stray comma between directives, and a `@` in a field name is the same defect
/// as a `@` in a directive name. One sentence is left over, and it is the one
/// this rule is named for: an argument that lists *no* field name.
///
/// cite(RFC 9111 § 5.2.2.7, label: private argument syntax): "This directive uses the quoted-string form of the argument syntax."
/// cite(RFC 9110 § 5.1): "A field name labels the corresponding field value as having the semantics defined by that name."
/// A `delta-seconds` argument, read in whichever of the two `cache-directive`
/// forms the sender wrote it, and the two things that can be wrong with it.
///
/// **The form first decides how the digits are found, and last decides whether
/// the form itself is the finding.** `cache-directive = token [ "=" ( token /
/// quoted-string ) ]`, so `max-age="60"` derives; § 5.2 has a recipient accept
/// both forms; and the directive's own subsection then says the sender was to
/// write the token form. The closing quote is the delimiter of an alternative
/// the grammar offers, not a character the `token` production refuses — which
/// is what this used to report, on a production the value satisfies.
///
/// **The digits are asked of what the form carries, and they are asked
/// first.** `max-age="abc"` is unreadable however it is spelled, and the
/// production it fails is the one that matters to every cache; the form is
/// what is left to say about an argument that *does* read.
// cite(RFC 9111 § 5.2): "cache-directive = token [ "=" ( token / quoted-string ) ]"
// cite(RFC 9111 § 5.2): "For the directives defined below that define arguments, recipients ought to accept both forms, even if a specific form is required for generation."
// cite(RFC 9111 § 5.2.2.1): "This directive uses the token form of the argument syntax: e.g., 'max-age=5' not 'max-age="5"'. A sender MUST NOT generate the quoted-string form."
fn delta_seconds_defect(name: &str, argument: &str, side: &str) -> Option<Defect> {
    let unquoted: String;
    let (digits, quoted): (&str, bool) = if argument.starts_with('"') {
        match crate::helpers::quoted_string::unescape_quoted_string(argument) {
            Ok(inner) => {
                unquoted = inner;
                (unquoted.as_str(), true)
            }
            Err(defect) => {
                return Some(Defect::named(
                    quoted_string_defect(defect),
                    format!(
                        "Invalid quoted-string in {} value: {}",
                        name,
                        defect.message(argument)
                    ),
                ))
            }
        }
    } else {
        if let Some(c) = crate::helpers::token::find_invalid_token_char(argument) {
            return Some(Defect::named(
                token_character(c),
                format!("{} value contains invalid character: '{}'", name, c),
            ));
        }
        (argument, false)
    };
    // cite(RFC 9111 § 1.2.2, label: delta-seconds): "delta-seconds  = 1*DIGIT"
    if let Some(c) = digits.chars().find(|ch| !ch.is_ascii_digit()) {
        return Some(Defect::named(
            &DELTA_SECONDS_CHARACTER_FORBIDDEN,
            format!(
                "{} must be a non-negative integer: {} is no `DIGIT`",
                name,
                crate::helpers::shown::describe_char(c),
            ),
        ));
    }
    if !quoted {
        return None;
    }
    // Which subsection said so, for the directive in front of us. `max-age` is
    // defined once per side; the other three once each. RFC 5861's two say
    // nothing about the form, and so nothing is said about theirs.
    let section = match (name.to_ascii_lowercase().as_str(), side) {
        ("max-age", "request") => "5.2.1.1",
        ("max-age", _) => "5.2.2.1",
        ("max-stale", _) => "5.2.1.2",
        ("min-fresh", _) => "5.2.1.3",
        ("s-maxage", _) => "5.2.2.10",
        _ => return None,
    };
    let token_form = match digits.is_empty() {
        true => String::new(),
        false => format!(", {name}={digits}"),
    };
    Some(Defect::named(
        &CACHE_CONTROL_ARGUMENT_QUOTED_FORM_FORBIDDEN,
        format!(
            "{name}={argument} writes the {name} argument in the quoted-string form; \
             RFC 9111 § {section} has a sender generate the token form{token_form}"
        ),
    ))
}

fn field_name_list_defect(name: &str, argument: &str) -> Vec<Defect> {
    let list = if argument.starts_with('"') {
        match crate::helpers::quoted_string::unescape_quoted_string(argument) {
            Ok(inner) => inner,
            // The quoting is what says where the list is, so a value that is
            // not a `quoted-string` holds no members to walk. This one still
            // ends the reading.
            Err(defect) => {
                return vec![Defect::named(
                    quoted_string_defect(defect),
                    format!(
                        "Invalid quoted-string in {} value: {}",
                        name,
                        defect.message(argument)
                    ),
                )]
            }
        }
    } else {
        // unquoted: allow single token or comma-separated tokens
        argument.to_string()
    };

    // The empty list and the empty element reach the same line below and are
    // not the same statement. `#field-name` is a plain `#`, so an argument of
    // nothing is a zero-element list the production generates — what is wrong
    // with `private=""` is that the *qualified* form is defined as listing one
    // or more field names, which is the directive's own subsection and no
    // production. `private=","` is the other one: an element a sender wrote and
    // left blank, which is the list's sender MUST NOT.
    // cite(RFC 9110 § 5.6.1): "#element => [ element ] *( OWS "," OWS [ element ] )"
    let lists_no_field = list.trim().is_empty();

    // Each name in this list is a field the sender chose to qualify the
    // directive with, and each is corrected on its own, so the walk answers
    // for every one of them. What is NOT a member's own defect is the hole
    // between two commas: `no-cache="a,,b"` names one field the sender left
    // blank however many times it did so, and the sentence names no field
    // because there is no field to name.
    let mut out: Vec<Defect> = Vec::new();
    let mut saw_an_empty_field = false;

    for field in list.split(',') {
        let field = field.trim();
        if field.is_empty() {
            saw_an_empty_field = true;
            continue;
        }
        if let Some(c) = crate::helpers::token::find_invalid_token_char(field) {
            // The finding names the field-name it is about. Two names in one
            // argument can fail on the same octet, and two copies of a sentence
            // that said only which octet would leave a reader unable to tell
            // how many names they have to change or which.
            out.push(Defect::named(
                token_character(c),
                format!(
                    "{} lists a field-name '{}' with an invalid character: '{}'",
                    name, field, c
                ),
            ));
        }
    }

    if saw_an_empty_field {
        let message = format!("Empty field-name in {} value", name);
        out.push(match lists_no_field {
            // Which of the two sentences governs is the directive name, and
            // the caller has it: each subsection defines its own qualified
            // form, so a finding here cites the paragraph the sender was
            // reaching for.
            true => Defect::named(qualified_form_lists_nothing(name), message),
            false => Defect::named(&LIST_MEMBER_EMPTY, message),
        });
    }

    out
}

/// The entry for a qualified form that lists no field name, chosen by the
/// directive that was written.
///
/// Both subsections state the same requirement for their own directive and the
/// two entries exist to keep that citation, so the mapping is the whole of the
/// difference between them. `private` is the fallback rather than a third arm:
/// only these two names reach here, and the compiler cannot say so.
fn qualified_form_lists_nothing(name: &str) -> &'static ViolationDef {
    match name.eq_ignore_ascii_case("no-cache") {
        true => &CACHE_CONTROL_NO_CACHE_ARGUMENT_EMPTY,
        false => &CACHE_CONTROL_PRIVATE_ARGUMENT_EMPTY,
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &CacheControlDirectiveValid;

#[cfg(test)]
mod tests {
    /// The cases below are values stating one defect, and this says so rather
    /// than taking the first of however many were reported. `run_rule` is
    /// `run_rule_all(..).into_iter().next()`, so a walk that starts answering
    /// twice about one field passes every one-defect case already written here
    /// and the regression is invisible to this file.
    fn one_finding(
        rule: &dyn crate::rules::Rule,
        tx: &crate::http_transaction::HttpTransaction,
        history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<crate::lint::Violation> {
        let mut found = crate::test_helpers::run_rule_all(rule, tx, history, cfg);
        assert!(
            found.len() <= 1,
            "this fixture is for values stating one defect; got {:?}",
            found.iter().map(|v| &v.message).collect::<Vec<_>>()
        );
        found.pop()
    }

    use super::*;
    use rstest::rstest;

    fn make_req(val: &str) -> crate::http_transaction::HttpTransaction {
        crate::test_helpers::make_test_transaction_with_headers(&[("cache-control", val)])
    }

    fn make_resp(val: &str) -> crate::http_transaction::HttpTransaction {
        crate::test_helpers::make_test_transaction_with_response(200, &[("cache-control", val)])
    }

    #[rstest]
    #[case("max-age=3600", false)]
    #[case("s-maxage=0", false)]
    #[case("private=Foo,bar", false)]
    #[case("private=Foo", false)]
    #[case("private=\"Set-Cookie, X-Foo\"", false)]
    #[case("private=", false)]
    // `no-cache` with a `#field-name` argument is § 5.2.2.4's response
    // directive; § 5.2.1.4's request one takes no argument, and these rows moved
    // to `response_cases` when the arity of each side was read.
    #[case("public, max-age=60", false)]
    #[case("foo=bar", false)]
    #[case("max-stale", false)]
    #[case("max-stale=10, min-fresh=5", false)]
    #[case("stale-if-error=60", false)]
    #[case("max-age=abc", true)]
    #[case("max-age=-1", true)]
    #[case("max-age=1.5", true)]
    #[case("s-maxage=1.5", true)]
    #[case("max-stale=abc", true)]
    #[case("min-fresh=1.5", true)]
    #[case("stale-if-error=soon", true)]
    #[case("max-age=\"3600\"", true)]
    #[case("max-stale=\"10\"", true)]
    #[case("min-fresh=\"5\"", true)]
    #[case("max-age=\"\"", true)]
    #[case("max-age=1!", true)]
    #[case("private=Set Cookie", true)]
    #[case("private=\"Set Cookie\"", true)]
    #[case("private=bad@val", true)]
    #[case("private=,", true)]
    #[case("private=\",\"", true)]
    #[case("ma x=1", true)]
    #[case("custom=\"unterminated", true)]
    fn request_cases(#[case] value: &str, #[case] expect_violation: bool) -> anyhow::Result<()> {
        let rule = CacheControlDirectiveValid;
        let tx = make_req(value);
        let v = one_finding(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        if expect_violation {
            assert!(v.is_some(), "expected violation for '{}', got none", value);
        } else {
            assert!(v.is_none(), "did not expect violation for '{}'", value);
        }
        Ok(())
    }

    #[rstest]
    #[case("max-age=3600", false)]
    #[case("s-maxage=0", false)]
    #[case("private=Foo,bar", false)]
    #[case("private=\"Set-Cookie, X-Foo\"", false)]
    #[case("private=", false)]
    #[case("foo=bar", false)]
    #[case("max-age=60, stale-while-revalidate=30, stale-if-error=60", false)]
    #[case("max-age=60, stale-while-revalidate=\"30\"", false)]
    #[case("max-age=abc", true)]
    #[case("stale-while-revalidate=soon", true)]
    #[case("max-age=\"3600\"", true)]
    #[case("s-maxage=\"60\"", true)]
    #[case("max-age=\"abc", true)]
    #[case("custom=\"unterminated", true)]
    #[case("max-age=1!", true)]
    #[case("private=,", true)]
    #[case("ma x=1", true)]
    fn response_cases(#[case] value: &str, #[case] expect_violation: bool) -> anyhow::Result<()> {
        let rule = CacheControlDirectiveValid;
        let tx = make_resp(value);
        let v = one_finding(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        if expect_violation {
            assert!(v.is_some(), "expected violation for '{}', got none", value);
        } else {
            assert!(v.is_none(), "did not expect violation for '{}'", value);
        }
        Ok(())
    }

    #[test]
    fn multiple_headers_valid() -> anyhow::Result<()> {
        let rule = CacheControlDirectiveValid;
        let tx = crate::test_helpers::make_test_transaction_with_headers(&[
            ("cache-control", "no-cache"),
            ("cache-control", "max-age=60"),
        ]);
        let v = one_finding(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn an_obs_text_octet_in_a_directive_name_is_a_token_defect() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        let rule = CacheControlDirectiveValid;
        let mut tx = crate::test_helpers::make_test_transaction();
        let bad = HeaderValue::from_bytes(&[0xff]).expect("should construct non-utf8 header");
        let mut hm = hyper::HeaderMap::new();
        hm.insert("cache-control", bad);
        tx.request.headers = hm;
        let v = one_finding(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        let v = v.expect("a finding");
        assert_eq!(v.violation, "token_character_forbidden");
        assert_eq!(
            v.message,
            "Invalid Cache-Control header in request: Cache-Control member '\u{ff}' has a \
             directive name containing an invalid character: 0xFF"
        );
        Ok(())
    }

    #[test]
    fn whitespace_only_request_is_allowed() -> anyhow::Result<()> {
        // Leading/trailing OWS is excluded from the field line value (RFC 9112
        // §5.1), so a whitespace-only value is an empty value: a legal
        // zero-element list, exactly like `empty_whole_value_is_allowed_request`.
        let rule = CacheControlDirectiveValid;
        let tx = make_req("   ");
        let v = one_finding(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(
            v.is_none(),
            "whitespace-only value is an empty field line value, i.e. a zero-element list"
        );
        Ok(())
    }

    #[test]
    fn whitespace_only_response_is_allowed() -> anyhow::Result<()> {
        let rule = CacheControlDirectiveValid;
        let tx = make_resp("   ");
        let v = one_finding(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(
            v.is_none(),
            "whitespace-only value is an empty field line value, i.e. a zero-element list"
        );
        Ok(())
    }

    #[test]
    fn private_unterminated_quoted_reports_violation() -> anyhow::Result<()> {
        let rule = CacheControlDirectiveValid;
        let tx = make_req("private=\"unterminated");
        let v = one_finding(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(
            v.is_some(),
            "unterminated quoted-string in private value should be a violation"
        );
        Ok(())
    }

    #[test]
    fn empty_member_is_violation() -> anyhow::Result<()> {
        let rule = CacheControlDirectiveValid;
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers =
            crate::test_helpers::make_headers_from_pairs(&[("cache-control", ",max-age=1")]);
        let v = one_finding(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn empty_whole_value_is_allowed_request() -> anyhow::Result<()> {
        // A wholly empty `Cache-Control:` is a legal zero-element list, unlike the
        // empty *element* in `empty_member_is_violation`.
        let rule = CacheControlDirectiveValid;
        let tx = make_req("");
        let v = one_finding(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none(), "empty Cache-Control is a zero-element list");
        Ok(())
    }

    #[test]
    fn empty_whole_value_is_allowed_response() -> anyhow::Result<()> {
        let rule = CacheControlDirectiveValid;
        let tx = make_resp("");
        let v = one_finding(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none(), "empty Cache-Control is a zero-element list");
        Ok(())
    }

    #[test]
    fn needs_no_response() {
        let rule = CacheControlDirectiveValid;
        assert!(!rule.needs_response());
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let rule = CacheControlDirectiveValid;
        let mut cfg = crate::config::Config::default();
        let mut table = toml::map::Map::new();
        table.insert("enabled".to_string(), toml::Value::Boolean(true));
        cfg.rules.insert(
            "cache_control_directive_valid".into(),
            toml::Value::Table(table),
        );

        // validate should succeed without error
        rule.prepare(&cfg)?;
        Ok(())
    }

    #[test]
    fn foo_empty_value_allowed() -> anyhow::Result<()> {
        let rule = CacheControlDirectiveValid;
        let tx = make_req("foo=");
        let v = one_finding(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn foo_quoted_value_allowed() -> anyhow::Result<()> {
        let rule = CacheControlDirectiveValid;
        let tx = make_req("foo=\"bar\"");
        let v = one_finding(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn directive_value_invalid_token() -> anyhow::Result<()> {
        let rule = CacheControlDirectiveValid;
        let tx = make_req("foo=bad@val");
        let v = one_finding(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        Ok(())
    }

    /// `delta-seconds = 1*DIGIT` sets no upper bound, and §1.2.2 tells a cache that
    /// receives an unrepresentable value to clamp it to 2147483648 rather than treat
    /// it as an error — so an oversized digit run is valid syntax, not a violation.
    #[rstest]
    #[case("max-age=18446744073709551616")]
    #[case("s-maxage=99999999999999999999999999")]
    fn oversized_delta_seconds_is_valid_syntax(#[case] value: &str) -> anyhow::Result<()> {
        let rule = CacheControlDirectiveValid;
        let tx = make_req(value);
        let v = one_finding(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none(), "unexpected violation for '{}': {:?}", value, v);
        Ok(())
    }

    #[test]
    fn empty_directive_name_is_violation() -> anyhow::Result<()> {
        let rule = CacheControlDirectiveValid;
        let tx = make_req("=bar");
        let v = one_finding(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn private_quoted_empty_field_is_violation() -> anyhow::Result<()> {
        let rule = CacheControlDirectiveValid;
        let tx = make_req("private=\"field1,,field3\"");
        let v = one_finding(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn private_quoted_invalid_field_char_is_violation() -> anyhow::Result<()> {
        let rule = CacheControlDirectiveValid;
        let tx = make_req("private=\"field1,bad@field\"");
        let v = one_finding(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        Ok(())
    }

    #[test]
    fn a_responses_obs_text_octet_is_the_same_token_defect() -> anyhow::Result<()> {
        use hyper::header::HeaderValue;
        let rule = CacheControlDirectiveValid;
        let mut tx = crate::test_helpers::make_test_transaction();
        let bad = HeaderValue::from_bytes(&[0xff]).expect("should construct non-utf8 header");
        let mut hm = hyper::HeaderMap::new();
        hm.insert("cache-control", bad);
        tx.response = Some(crate::http_transaction::ResponseInfo {
            status: 200,
            version: "HTTP/1.1".into(),
            headers: hm,

            body_length: None,
            body_interrupted: false,
            trailers: None,
        });
        let v = one_finding(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        let v = v.expect("a finding");
        assert_eq!(v.violation, "token_character_forbidden");
        assert_eq!(
            v.message,
            "Invalid Cache-Control header in response: Cache-Control member '\u{ff}' has a \
             directive name containing an invalid character: 0xFF"
        );
        Ok(())
    }

    #[test]
    fn whitespace_around_name_value_accepted() -> anyhow::Result<()> {
        let rule = CacheControlDirectiveValid;
        let tx = make_req(" max-age = 3600 ");
        let v = one_finding(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
        Ok(())
    }

    #[test]
    fn quoted_string_with_extra_chars_reports_violation() -> anyhow::Result<()> {
        let rule = CacheControlDirectiveValid;
        let tx = make_req("foo=\"bar\"x");
        let v = one_finding(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_some());
        Ok(())
    }

    /// Every finding whose defect belongs to a production RFC 9111 imports,
    /// with the id it now carries. The rows are the whole of this rule's
    /// borrowed half: the list construct around the directives, the list
    /// construct *inside* a qualified argument, the `token` a directive name, a
    /// directive value and a `field-name` all have to be, and the
    /// `quoted-string` either of the two argument forms may use.
    #[rstest]
    #[case(",max-age=1", "list_member_empty")]
    #[case("private=\"field1,,field3\"", "list_member_empty")]
    #[case("=bar", "token_empty")]
    #[case("ma x=1", "token_whitespace_or_control_forbidden")]
    #[case("ma@x=1", "token_character_forbidden")]
    #[case("max-age=1@2", "token_character_forbidden")]
    #[case("foo=bad@val", "token_character_forbidden")]
    #[case("private=\"field1,bad@field\"", "token_character_forbidden")]
    #[case("private=\"Set Cookie\"", "token_whitespace_or_control_forbidden")]
    #[case("custom=\"unterminated", "quoted_string_delimiter_missing")]
    #[case("private=\"unterminated", "quoted_string_delimiter_missing")]
    fn a_borrowed_production_reports_the_id_of_the_production(
        #[case] value: &str,
        #[case] id: &str,
    ) {
        assert_eq!(judge(value).violation, id, "{value}");
    }

    /// The two rules that read this field's members answer with one id apiece
    /// for the defects they share.
    ///
    /// The last column is where the sentence comes from. For the member's own
    /// grammar the reader words the finding and both rules pass its sentence on
    /// unchanged — prose deduplicated by sharing code, which was possible
    /// before any of this. For the argument each rule words the finding itself,
    /// and the two texts now agree as well: once these walks collect rather
    /// than stop at the first defective member, a finding has to name the
    /// directive it is about, and there is one true way to say which directive
    /// carried the character. **Which leaves the two rules drawing one entry
    /// with one sentence for every shape in this table**, which is what the
    /// duplicate Q6 asks about looks like from inside.
    #[test]
    fn both_cache_control_syntax_rules_report_one_id_for_one_mistake() {
        let judge_with = |rule: &dyn crate::rules::Rule, value: &str| -> Violation {
            let mut tx = crate::test_helpers::make_test_transaction();
            tx.request.headers =
                crate::test_helpers::make_headers_from_pairs(&[("cache-control", value)]);
            one_finding(
                rule,
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
            )
            .unwrap_or_else(|| panic!("{}: {value}", rule.id()))
        };

        for (value, id, one_sentence) in [
            ("no-cache,,foo", "list_member_empty", true),
            ("=abc", "token_empty", true),
            ("foo=bad@value", "token_character_forbidden", true),
            (
                "foo=\"unterminated",
                "quoted_string_delimiter_missing",
                true,
            ),
        ] {
            let directive = judge_with(&CacheControlDirectiveValid, value);
            let token = judge_with(
                &crate::rules::cache_control_token_valid::CacheControlTokenValid,
                value,
            );
            assert_eq!(directive.violation, id, "{value}");
            assert_eq!(token.violation, id, "{value}");
            assert_eq!(directive.message == token.message, one_sentence, "{value}");
        }
    }

    /// What this rule is named for turned out to be a production after all, and
    /// the reason is the directive's *name*. `-1` and `1.5` are well-formed
    /// tokens, so the `cache-directive` is intact — but § 5.2.2.1 gives
    /// `max-age`'s argument the syntax `delta-seconds`, which is where the value
    /// says which grammar it meant. `Age` reports the same id for the same
    /// octet with no directive in front of it.
    #[rstest]
    #[case("max-age=-1")]
    #[case("max-age=1.5")]
    #[case("s-maxage=1.5")]
    #[case("max-age=abc")]
    #[case("max-stale=abc")]
    #[case("min-fresh=1.5")]
    #[case("stale-while-revalidate=soon")]
    #[case("stale-if-error=-1")]
    #[case("max-age=\"abc\"")]
    #[case("max-age=\" 5\"")]
    fn a_directives_argument_syntax_is_a_production_the_name_commits_it_to(#[case] value: &str) {
        assert_eq!(
            judge(value).violation,
            "delta_seconds_character_forbidden",
            "{value}"
        );
    }

    /// A well-formed `quoted-string` is the other alternative of the argument
    /// grammar, not a `token` with a bad character in it. What refuses
    /// `max-age="60"` is the directive's own subsection, which has a sender
    /// write the token form — so the id is the subject's, the message names the
    /// section the directive in front of it was read against, and it names the
    /// spelling that would have satisfied it.
    #[rstest]
    #[case::request_max_age("max-age=\"5\"", true, "5.2.1.1", "max-age=5")]
    #[case::max_stale("max-stale=\"10\"", true, "5.2.1.2", "max-stale=10")]
    #[case::min_fresh("min-fresh=\"20\"", true, "5.2.1.3", "min-fresh=20")]
    #[case::response_max_age("max-age=\"5\"", false, "5.2.2.1", "max-age=5")]
    #[case::s_maxage("s-maxage=\"10\"", false, "5.2.2.10", "s-maxage=10")]
    #[case::case_of_the_name("Max-Age=\"5\"", false, "5.2.2.1", "Max-Age=5")]
    fn a_quoted_delta_seconds_argument_is_a_form_the_directive_refuses(
        #[case] value: &str,
        #[case] request: bool,
        #[case] section: &str,
        #[case] token_form: &str,
    ) {
        let v = match request {
            true => judge(value),
            false => judge_response(value),
        };
        assert_eq!(
            v.violation, "cache_control_argument_quoted_form_forbidden",
            "{value}"
        );
        assert!(v.message.contains(value), "{}", v.message);
        assert!(v.message.contains(section), "{}", v.message);
        assert!(v.message.contains(token_form), "{}", v.message);
        assert!(!v.message.contains("invalid character"), "{}", v.message);
    }

    /// RFC 5861 prints `"=" delta-seconds` and says nothing about a
    /// quoted-string form, so nothing is said about it here: the digits are
    /// still asked, and a well-formed quoted argument that carries them is left
    /// alone rather than charged under a sentence another document wrote about
    /// other directives.
    #[test]
    fn the_extension_directives_are_asked_their_digits_and_not_their_form() {
        let rule = CacheControlDirectiveValid;
        let cfg = crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]);
        let quiet = one_finding(
            &rule,
            &make_resp("max-age=60, stale-while-revalidate=\"30\", stale-if-error=\"60\""),
            &crate::transaction_history::TransactionHistory::empty(),
            &cfg,
        );
        assert!(quiet.is_none(), "{quiet:?}");
        assert_eq!(
            judge_response("stale-while-revalidate=\"soon\"").violation,
            "delta_seconds_character_forbidden"
        );
    }

    /// The statement with no production behind it: each directive's subsection
    /// defines the qualified form as listing *one or more* field names, and no
    /// imported grammar says a `#field-name` may not be empty — `#` generates
    /// it. The requirement is written once per directive, so the id says which
    /// paragraph the finding is against.
    #[rstest]
    #[case("private=\"\"", "cache_control_private_argument_empty")]
    #[case("PRIVATE=\"\"", "cache_control_private_argument_empty")]
    fn an_argument_listing_no_field_names_the_directives_own_sentence(
        #[case] value: &str,
        #[case] id: &str,
    ) {
        assert_eq!(judge(value).violation, id, "{value}");
    }

    /// **`no-cache`'s qualified form is § 5.2.2.4's, and § 5.2.2.4 is about a
    /// response.**
    ///
    /// The rows above used to include these two and read them out of a request,
    /// which is the one fixture that made the claim untrue: a client writing
    /// `no-cache=""` was told its argument listed no field name, against a
    /// paragraph defining a directive it had not sent. The same octets on the
    /// two sides are two directives, and the second column is what the request
    /// side owes instead.
    #[rstest]
    #[case("no-cache=\"\"", "cache_control_no_cache_argument_empty")]
    #[case("No-Cache=\" \"", "cache_control_no_cache_argument_empty")]
    fn the_qualified_no_cache_is_read_where_its_paragraph_defines_it(
        #[case] value: &str,
        #[case] id: &str,
    ) {
        assert_eq!(judge_response(value).violation, id, "{value}");
        assert_eq!(
            judge(value).violation,
            "cache_control_directive_argument_forbidden",
            "{value} in a request",
        );
    }

    /// One line, two statements, and the argument syntax is what separates
    /// them. `#field-name` generates the empty list, so an argument listing
    /// nothing breaks the directive's definition of the qualified form and not
    /// § 5.6.1.1's MUST NOT — which forbids an element a sender wrote and left
    /// blank, and is exactly what the comma in the second value is.
    #[test]
    fn the_empty_list_and_the_empty_element_are_two_statements() {
        let empty_list = judge("private=\"\"");
        let empty_element = judge("private=\",\"");
        assert_eq!(empty_list.message, empty_element.message);
        assert_eq!(empty_list.violation, "cache_control_private_argument_empty");
        assert_eq!(empty_element.violation, "list_member_empty");
    }

    /// Read a value's first finding, which every assertion above wants.
    fn judge(value: &str) -> Violation {
        let rule = CacheControlDirectiveValid;
        one_finding(
            &rule,
            &make_req(value),
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
        .unwrap_or_else(|| panic!("expected a finding for '{value}'"))
    }

    /// The same reading of a response's field, for the directives defined on
    /// that side.
    fn judge_response(value: &str) -> Violation {
        let rule = CacheControlDirectiveValid;
        one_finding(
            &rule,
            &make_resp(value),
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        )
        .unwrap_or_else(|| panic!("expected a finding for '{value}'"))
    }

    #[test]
    fn multiple_directives_unquoted_comma_accepted() -> anyhow::Result<()> {
        let rule = CacheControlDirectiveValid;
        let tx = make_req("foo=bar,baz");
        let v = one_finding(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert!(v.is_none());
        Ok(())
    }

    /// Each directive states its own argument syntax, so a `max-age` whose
    /// digits are letters and a `private` naming no field name are two
    /// corrections. Neither finding is the other's, and each names its
    /// directive.
    #[test]
    fn a_value_with_two_bad_arguments_answers_about_both() {
        let rule = CacheControlDirectiveValid;
        let tx = make_resp("max-age=abc, private=\"\"");
        let found = crate::test_helpers::run_rule_all(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        let ids: Vec<&str> = found.iter().map(|v| v.violation.as_str()).collect();
        assert_eq!(
            ids,
            vec![
                "delta_seconds_character_forbidden",
                "cache_control_private_argument_empty"
            ],
            "{:?}",
            found.iter().map(|v| &v.message).collect::<Vec<_>>()
        );
        assert!(found[0].message.contains("max-age"), "{}", found[0].message);
        assert!(found[1].message.contains("private"), "{}", found[1].message);
    }

    /// The qualified form's argument is a list of its own, and each name in it
    /// is a field the sender chose and corrects on its own. Walking to the
    /// first bad one said `a b` was wrong and left `c@d` for the next run.
    #[test]
    fn every_field_name_a_qualified_directive_lists_is_read() {
        let rule = CacheControlDirectiveValid;
        let tx = make_resp("no-cache=\"a b, c@d\"");
        let found = crate::test_helpers::run_rule_all(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        let ids: Vec<&str> = found.iter().map(|v| v.violation.as_str()).collect();
        assert_eq!(
            ids,
            vec![
                "token_whitespace_or_control_forbidden",
                "token_character_forbidden"
            ],
            "{:?}",
            found.iter().map(|v| &v.message).collect::<Vec<_>>()
        );
        // Each names the field-name it is about. Two names failing on the same
        // octet would otherwise be one sentence written twice.
        assert!(found[0].message.contains("'a b'"), "{}", found[0].message);
        assert!(found[1].message.contains("'c@d'"), "{}", found[1].message);
    }

    /// Two field-names that fail on the *same* octet are still two names, and
    /// the only thing telling them apart is the subject in the sentence.
    #[test]
    fn two_field_names_failing_alike_are_two_sentences() {
        let rule = CacheControlDirectiveValid;
        let tx = make_resp("private=\"a@b, c@d\"");
        let found = crate::test_helpers::run_rule_all(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        assert_eq!(found.len(), 2, "{found:?}");
        assert_ne!(found[0].message, found[1].message, "{found:?}");
    }

    /// The hole between two commas belongs to the argument, not to a field
    /// name: three of them are one blank the sender left.
    #[test]
    fn a_qualified_argument_states_its_empty_field_name_once() {
        let rule = CacheControlDirectiveValid;
        let tx = make_resp("no-cache=\"a,,,b\"");
        let found = crate::test_helpers::run_rule_all(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        let ids: Vec<&str> = found.iter().map(|v| v.violation.as_str()).collect();
        assert_eq!(ids, vec!["list_member_empty"], "{found:?}");
    }

    /// The same reading of the same list its neighbour makes: however many gaps
    /// the value carries, the list is empty-membered once.
    #[test]
    fn a_value_written_with_gaps_states_its_emptiness_once() {
        let rule = CacheControlDirectiveValid;
        let tx = make_resp("max-age=abc, , , no-cache=\"\"");
        let found = crate::test_helpers::run_rule_all(
            &rule,
            &tx,
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
        );
        let ids: Vec<&str> = found.iter().map(|v| v.violation.as_str()).collect();
        assert_eq!(
            ids,
            vec![
                "delta_seconds_character_forbidden",
                "cache_control_no_cache_argument_empty",
                "list_member_empty"
            ],
            "{:?}",
            found.iter().map(|v| &v.message).collect::<Vec<_>>()
        );
    }
    /// **RFC 9111 § 5.2's arity, read as the three-valued fact it is, on both
    /// sides of the exchange.**
    ///
    /// The rows are every directive the document defines, in all three
    /// spellings a sender can write — bare, with an argument, and with an `=`
    /// and nothing after it — and the ids are asserted as a whole list rather
    /// than a first finding, because a walk that collects can lose a second
    /// answer without any row here changing.
    ///
    /// Three columns of it are the point.
    ///
    /// - **`no-cache` is two directives with one spelling.** § 5.2.2.4 gives the
    ///   response one a `#field-name` and § 5.2.1.4 gives the request one
    ///   nothing, so `no-cache="Set-Cookie"` is conforming in one column and a
    ///   finding in the other. A table keyed on the name alone cannot hold both.
    /// - **A directive defined on one side keeps its arity on the other.**
    ///   § 5.2's sentence is about the directives the document defines, not
    ///   about which half of an exchange carries them, so `only-if-cached=1` is
    ///   a finding in a response too. Whether the directive belongs there at all
    ///   is a different sentence and no reading here makes it.
    /// - **The `=`-and-nothing form is nobody's arity finding**, on either side
    ///   and for every directive: it derives from no `cache-directive`, and the
    ///   entry for the production it broke is the whole answer. Two findings
    ///   there would be two corrections for one deleted character.
    #[rstest]
    // an argument syntax, and no meaning defined without one
    #[case("max-age", &["cache_control_directive_argument_missing"], &["cache_control_directive_argument_missing"])]
    #[case("min-fresh", &["cache_control_directive_argument_missing"], &["cache_control_directive_argument_missing"])]
    #[case("s-maxage", &["cache_control_directive_argument_missing"], &["cache_control_directive_argument_missing"])]
    #[case("max-age=60", &[], &[])]
    // an argument syntax, and the subsection says what the bare form means
    #[case("max-stale", &[], &[])]
    #[case("private", &[], &[])]
    #[case("private=\"Set-Cookie\"", &[], &[])]
    // one spelling, two definitions: § 5.2.1.4 request, § 5.2.2.4 response
    #[case("no-cache", &[], &[])]
    #[case("no-cache=\"Set-Cookie\"", &["cache_control_directive_argument_forbidden"], &[])]
    // no argument syntax at all, so § 5.2's sentence is the whole answer
    #[case("no-store", &[], &[])]
    #[case("no-store=1", &["cache_control_directive_argument_forbidden"], &["cache_control_directive_argument_forbidden"])]
    #[case("no-transform=1", &["cache_control_directive_argument_forbidden"], &["cache_control_directive_argument_forbidden"])]
    #[case("only-if-cached=1", &["cache_control_directive_argument_forbidden"], &["cache_control_directive_argument_forbidden"])]
    #[case("public=1", &["cache_control_directive_argument_forbidden"], &["cache_control_directive_argument_forbidden"])]
    #[case("must-revalidate=1", &["cache_control_directive_argument_forbidden"], &["cache_control_directive_argument_forbidden"])]
    #[case("must-understand=1", &["cache_control_directive_argument_forbidden"], &["cache_control_directive_argument_forbidden"])]
    #[case("proxy-revalidate=1", &["cache_control_directive_argument_forbidden"], &["cache_control_directive_argument_forbidden"])]
    // a directive this document does not define states its arity elsewhere
    #[case("immutable", &[], &[])]
    #[case("immutable=1", &[], &[])]
    #[case("community=\"UCI\"", &[], &[])]
    #[case("stale-while-revalidate=30", &[], &[])]
    // the `=` with nothing after it, which the production refuses first
    #[case("max-age=", &[], &[])]
    #[case("no-store=", &[], &[])]
    #[case("public=", &[], &[])]
    fn a_directive_takes_the_argument_its_own_subsection_defines(
        #[case] value: &str,
        #[case] in_request: &[&str],
        #[case] in_response: &[&str],
    ) {
        let rule = CacheControlDirectiveValid;
        for (tx, expected, side) in [
            (make_req(value), in_request, "request"),
            (make_resp(value), in_response, "response"),
        ] {
            let found = crate::test_helpers::run_rule_all(
                &rule,
                &tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &crate::test_helpers::make_test_config_with_enabled_rules(&[rule.id()]),
            );
            let ids: Vec<&str> = found.iter().map(|v| v.violation.as_str()).collect();
            assert_eq!(
                ids,
                expected,
                "{side} `{value}`: {:?}",
                found.iter().map(|v| &v.message).collect::<Vec<_>>()
            );
        }
    }

    /// The `=` with nothing after it is answered, and answered once, by the
    /// entry for the production it breaks.
    ///
    /// The row above holds that the arity reading declines it. This holds the
    /// other half of that claim — that declining it leaves nothing unsaid — by
    /// asking the rule that owns the production what it draws. Without this,
    /// "the empty form is somebody else's finding" is a premise about a
    /// neighbour, and § 7 has those go stale.
    #[rstest]
    #[case("max-age=")]
    #[case("no-store=")]
    #[case("public=")]
    fn the_empty_argument_stays_the_productions_finding(#[case] value: &str) {
        let found = crate::test_helpers::run_rule_all(
            &crate::rules::cache_control_token_valid::CacheControlTokenValid,
            &make_resp(value),
            &crate::transaction_history::TransactionHistory::empty(),
            &crate::test_helpers::make_test_config_with_enabled_rules(&[
                "cache_control_token_valid",
            ]),
        );
        let ids: Vec<&str> = found.iter().map(|v| v.violation.as_str()).collect();
        assert_eq!(ids, vec!["cache_control_directive_value_empty"], "{value}");
    }

    /// **The arity table names every directive RFC 9111 defines, and nothing
    /// else.**
    ///
    /// A silence in this table is invisible from outside it: a directive left
    /// out simply never draws either entry, which reads exactly like a
    /// directive the document permits both ways. So the table is asserted
    /// against the list rather than sampled — § 5.2.1 defines seven and § 5.2.2
    /// defines ten, `max-age`, `no-cache`, `no-store` and `no-transform` being
    /// the four written twice — and the arms that are not `Optional` are
    /// asserted to be the ones whose subsection prints no argument syntax or
    /// prints one without defining the bare form.
    #[test]
    fn the_arity_table_is_rfc_9111_s_own_list_of_directives() {
        let request = [
            "max-age",
            "max-stale",
            "min-fresh",
            "no-cache",
            "no-store",
            "no-transform",
            "only-if-cached",
        ];
        let response = [
            "max-age",
            "must-revalidate",
            "must-understand",
            "no-cache",
            "no-store",
            "no-transform",
            "private",
            "proxy-revalidate",
            "public",
            "s-maxage",
        ];
        for (side, names) in [
            ("request", request.as_slice()),
            ("response", response.as_slice()),
        ] {
            for name in names {
                assert!(
                    arity(name, side).is_some(),
                    "{side} `{name}` is defined by RFC 9111 § 5.2 and the arity table omits it, \
                     so neither arity entry can ever fire on it",
                );
            }
        }
        for name in [
            "immutable",
            "stale-while-revalidate",
            "stale-if-error",
            "community",
        ] {
            for side in ["request", "response"] {
                assert!(
                    arity(name, side).is_none(),
                    "`{name}` is defined outside RFC 9111 and this table judges it anyway",
                );
            }
        }
    }
}
