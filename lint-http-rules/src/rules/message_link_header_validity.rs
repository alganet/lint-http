// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

use crate::helpers::headers::{
    combined_field_value_as_written, describe_char, parse_token_bws_word, shown_in_finding,
    split_semicolons_respecting_quotes, trim_ows,
};
use crate::helpers::uri::{find_non_uri_char, validate_scheme_name};
use crate::lint::Violation;
use crate::rules::Rule;

pub struct MessageLinkHeaderValidity;

impl Rule for MessageLinkHeaderValidity {
    fn id(&self) -> &'static str {
        "message_link_header_validity"
    }

    /// Either direction of an exchange writes this field.
    ///
    /// RFC 8288 defines `Link` as a serialisation of links "into HTTP headers"
    /// and states no direction anywhere: its IANA registration names the
    /// protocol and not a message type, and § 3.2's default link context is
    /// *the representation the field is associated with*, which a request
    /// carrying content has as surely as a response does. The gate this
    /// replaces was a comment — *"Link is meaningful on responses / 103 Early
    /// Hints"* — with no document behind it, and it cost the grammar checks
    /// every `Link` a client ever sent.
    ///
    /// One finding stays response-only, and it is gated where it is made
    /// rather than here: the HTML processing model that discards a `preload`
    /// member with no `as` runs over a *response*'s header list.
    // cite(RFC 8288 § 3): "The Link header field provides a means for serialising one or more links into HTTP headers."
    fn scope(&self) -> crate::rules::RuleScope {
        crate::rules::RuleScope::Both
    }

    fn check_transaction(
        &self,
        tx: &crate::http_transaction::HttpTransaction,
        _history: &crate::transaction_history::TransactionHistory,
        cfg: &crate::config::Config,
    ) -> Option<Violation> {
        // Most messages carry no `Link`, and the config read is several map
        // probes and a hash of the rule id against one lookup per section.
        if !tx.request.headers.contains_key("link")
            && !tx
                .response
                .as_ref()
                .is_some_and(|resp| resp.headers.contains_key("link"))
        {
            return None;
        }

        let config = crate::rules::parse_rule_config(cfg, self.id()).ok()?;

        let message = judge(&tx.request.headers, "Request", false).or_else(|| {
            tx.response
                .as_ref()
                .and_then(|resp| judge(&resp.headers, "Response", true))
        })?;

        Some(Violation {
            rule: self.id().into(),
            severity: config.severity,
            message,
        })
    }

    fn description(&self) -> &'static str {
        "Parses the `Link` field of a request and of a response — every field line of one section \
         joined into the single list they are — against the grammar RFC 8288 §3 writes for it: \
         `Link = #link-value`, `link-value = \"<\" URI-Reference \">\" *( OWS \";\" OWS \
         link-param )` and `link-param = token BWS [ \"=\" BWS ( token / quoted-string ) ]`. On \
         top of the grammar it reports the three requirements the document states about a member: \
         that `rel` is present, that `rel` and the four attributes §3.4.1 bounds appear at most \
         once, and that each relation type derives from one of the two productions §3.3 offers. \
         Two of §3.4.1's per-attribute value grammars are measured after unquoting, through the \
         imports §1.1 makes by name: `hreflang` against RFC 5646's `Language-Tag` and `type` \
         against RFC 6838 §4.2's `type-name \"/\" subtype-name`.\
         \n\n\
         **A `type` value is measured against `restricted-name`, not `token`, and it has no \
         parameters.** §3.4.1's ABNF for the value ends at the subtype-name, so \
         `type=\"text/html;charset=utf-8\"` derives from nothing — the `;` is an octet \
         `restricted-name-chars` does not admit, not the start of a parameters group — and \
         `restricted-name` opens on a letter or digit, so `type=\"*/*\"` is a finding here where \
         `Accept`'s own grammar makes the same characters a media range. The hint itself binds \
         nothing: the document says in as many words that it does not override `Content-Type`, \
         and this rule reads the value's grammar, never the response it points at.\
         \n\n\
         **The `hreflang` check is the catalogue's conservative Language-Tag floor.** The shared \
         validator enforces what RFC 5646 §2.1's prose states — alphanumeric subtags, \
         hyphen-separated, at most eight characters, a first subtag of letters — and deliberately \
         not the full ABNF, because quoting more would claim a check not performed. Every \
         occurrence is judged: repeating the attribute is conforming (it is §3.4.1's way of \
         saying several languages are available), and each repetition still owes the production.\
         \n\n\
         **A relation type may be a URI, and that is the document's own example.** \
         `relation-type = reg-rel-type / ext-rel-type`, where `ext-rel-type = URI` — so \
         `Link: </>; rel=\"http://example.net/foo\"`, printed in §3.5, derives from the grammar. \
         Measuring a relation type against `tchar` reports every extension relation type there \
         is, because a URI holds `:` and `/` and a `token` holds neither. `reg-rel-type` is \
         narrower than `token` in the other direction — `LOALPHA *( LOALPHA / DIGIT / \".\" / \
         \"-\" )` admits no capital and no `_` — so the two productions are checked as the \
         alternation they are, and a value matching neither is named against both.\
         \n\n\
         **A link-param may have no value.** The `=` and the word after it are inside the \
         optional group, so `Link: <https://example.com/>; rel=next; nofollow` is a conforming \
         member. What the document does require is a *word* once the `=` is written, which is why \
         `rel=` is still reported.\
         \n\n\
         **Commas inside a member are data.** A `URI-Reference` admits `,` as a `sub-delim` and a \
         `quoted-string` admits it as `qdtext`; §3.3 says so in as many words when it requires an \
         extension relation type to be quoted if it holds one. The members are therefore cut at \
         the commas outside both `<>` and `\"\"`, and `Link: </a,b>; rel=next` is one link and not \
         two malformed ones.\
         \n\n\
         **What §3.4.1's `as` finding rests on, and where.** No RFC requires an `as` parameter of \
         anything: `preload` and `as` are HTML's, and the sentence that makes their pairing \
         observable is in the HTML Standard's *Processing `Link` headers* algorithm, which runs \
         over a **response**'s header list and returns early when `attribs[\"as\"]` does not \
         exist. So the member is not malformed — it is discarded by the recipient it was written \
         for, and the finding says that rather than inventing a requirement. On a request it is \
         not reported at all, because that algorithm never sees one.\
         \n\n\
         **RFC 8297 requires nothing of a `Link` in a 103.** Its five modals are two MUST NOTs \
         and a SHOULD NOT addressed to the client about what it does with fields it received, \
         plus two MAYs handed to the server; none of them is about this field's content. The \
         status-gated check this replaces asked a 103's members for a `rel` and let every other \
         response omit it — a narrower rendering of §3.3's MUST, which is stated once for every \
         link-value there is.\
         \n\n\
         **What this rule does not decide.**\
         \n\n\
         - **What a `media` value holds.** §1.1 imports its production — `media-query-list` — \
         from the dated 2012 CSS3 Media Queries Recommendation: a grammar in CSS's formalism \
         rather than ABNF, from a document this catalogue does not read, whose own error \
         handling folds a query it cannot parse to `not all` rather than refusing it. Measuring \
         a value against the pinned 2012 grammar would adjudicate a drift this catalogue has not \
         audited — the Media Queries syntax senders write today derives range forms the 2012 \
         document does not print — and a floor loose enough to sidestep the drift would measure \
         nothing. §3.4.1's one MUST about the value (quote it if it holds a `;` or `,`) needs no \
         rule, because the serialisation enforces it itself: unquoted, those characters are this \
         field's own delimiters, so the value never arrives as one value to ask about.\
         \n\
         - **Whether an `as` value names a preload destination.** The same HTML algorithm drops \
         the member when `as` translates to nothing, but the set of destinations lives in Fetch \
         and would have to be transcribed and kept in step here. Being wrong about it costs a \
         false report on an otherwise conforming member, so the question is carried rather than \
         guessed at.\
         \n\
         - **Where a relative `URI-Reference` resolves.** §3.1 and §3.2 make that a parser's MUST \
         and it needs a base the field does not carry.\
         \n\
         - **`rev`.** §3.3 deprecates it in a sentence holding no BCP 14 keyword at all, so \
         nothing there makes writing it a defect.\
         \n\
         - **Whether the target exists, or the relation type is registered.** §2.1.1.2 registers \
         relation types under Specification Required and §2.1.2 hands every unregistered name to \
         the URI form, so an unrecognised lowercase name is an extension the registry has not \
         been asked about — not a finding."
    }

    fn specifications(&self) -> &'static [crate::rules::SpecRef] {
        &[
            crate::rules::SpecRef {
                spec: "RFC 8288",
                section: Some("3"),
                url: "https://www.rfc-editor.org/rfc/rfc8288.html#section-3",
                note: "The serialisation: `Link = #link-value`, the angle-bracketed \
                       `URI-Reference`, and `link-param = token BWS [ \"=\" BWS ( token / \
                       quoted-string ) ]` — whose optional group is what makes a valueless \
                       parameter conforming. Also the sentence equating the token and \
                       quoted-string forms, which is why a value is judged after unquoting",
            },
            crate::rules::SpecRef {
                spec: "RFC 8288",
                section: Some("3.1"),
                url: "https://www.rfc-editor.org/rfc/rfc8288.html#section-3.1",
                note: "The link target: one IRI converted to a `URI-Reference` and written inside \
                       angle brackets. The conversion is why an octet no URI admits is a finding \
                       rather than an encoding question",
            },
            crate::rules::SpecRef {
                spec: "RFC 8288",
                section: Some("3.3"),
                url: "https://www.rfc-editor.org/rfc/rfc8288.html#section-3.3",
                note: "`rel` MUST be present and MUST NOT appear more than once; its value is \
                       `relation-type *( 1*SP relation-type )`; `relation-type = reg-rel-type / \
                       ext-rel-type` with `ext-rel-type = URI`, required to be absolute. The \
                       section that makes a URI-shaped relation type conforming and a capital \
                       letter in a registered one not",
            },
            crate::rules::SpecRef {
                spec: "RFC 8288",
                section: Some("3.4.1"),
                url: "https://www.rfc-editor.org/rfc/rfc8288.html#section-3.4.1",
                note: "The four serialisation-defined attributes this document bounds to one \
                       occurrence — `media`, `title`, `title*`, `type` — each in its own MUST \
                       NOT. `hreflang` is the one it deliberately leaves unbounded, saying that \
                       repeating it means several languages are available. Also the per-attribute \
                       value ABNFs: `Language-Tag` for `hreflang`, `type-name \"/\" \
                       subtype-name` for `type`, and `media-query-list` for `media` — the first \
                       two measured here, the third declined for the reasons the description \
                       gives",
            },
            crate::rules::SpecRef {
                spec: "RFC 8288",
                section: Some("2.1.1"),
                url: "https://www.rfc-editor.org/rfc/rfc8288.html#section-2.1.1",
                note: "Registered relation type names conform to `reg-rel-type` and are compared \
                       case-insensitively — the sentence behind folding case when asking whether \
                       a relation type is `preload`",
            },
            crate::rules::SpecRef {
                spec: "RFC 8288",
                section: Some("2.1.2"),
                url: "https://www.rfc-editor.org/rfc/rfc8288.html#section-2.1.2",
                note: "Extension relation types are URIs that uniquely identify the relation, \
                       compared as strings. Why a value matching no registered spelling is \
                       measured as a URI rather than reported",
            },
            crate::rules::SpecRef {
                spec: "RFC 8288",
                section: Some("2.2"),
                url: "https://www.rfc-editor.org/rfc/rfc8288.html#section-2.2",
                note: "Target attribute names are compared case-insensitively — the MUST behind \
                       recognising `rel`, `as` and the bounded four whatever case they were \
                       written in. Its `SHOULD NOT include \"%\", \"'\", or \"*\"` is advice \
                       about portability across serialisations and is not enforced here: §3.4.1 \
                       of this same document defines `title*`",
            },
            crate::rules::SpecRef {
                spec: "RFC 8288",
                section: Some("1.1"),
                url: "https://www.rfc-editor.org/rfc/rfc8288.html#section-1.1",
                note: "Which document's notation governs: the `#rule`, `token`, `quoted-string`, \
                       `BWS`, `OWS` and `LOALPHA` are imported rather than redefined, so the \
                       shared helpers that transcribe them are the right readers here. Its \
                       second list imports the value productions by name — `URI` and \
                       `URI-Reference` from RFC 3986, `type-name` and `subtype-name` from \
                       RFC 6838, `Language-Tag` from RFC 5646, and `media-query-list` from the \
                       2012 CSS3 Media Queries Recommendation, which is why a `media` value is \
                       the one this rule does not measure",
            },
            crate::rules::SpecRef {
                spec: "RFC 8288",
                section: Some("1.2"),
                url: "https://www.rfc-editor.org/rfc/rfc8288.html#section-1.2",
                note: "The bridge to a modal: this document states no requirement of its own that \
                       a value match its ABNF, it adopts the core specification's conformance \
                       section — which is RFC 9110 §2.2 in the document now in force",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("2.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-2.2",
                note: "The sender MUST NOT behind every grammar finding here: a member deriving \
                       from none of §3's productions is a protocol element matching no ABNF rule",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("5.6.1.1"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1.1",
                note: "The list construct: `#` sets no minimum, so an empty `Link:` declares no \
                       link rather than declaring one badly — and a sender MUST NOT write an \
                       empty element between two real ones",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("5.6.3"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.3",
                note: "`BWS` is admitted beside the `=` for historical reasons and a sender MUST \
                       NOT generate it — the half of the production that makes the recipient's \
                       trim required and the sender's whitespace a finding",
            },
            crate::rules::SpecRef {
                spec: "RFC 9110",
                section: Some("5.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.2",
                note: "Repeated `Link` field lines are one list. RFC 8288 §3.5 shows the same \
                       thing from the other side, printing a two-member field value and the two \
                       field lines it is equivalent to",
            },
            crate::rules::SpecRef {
                spec: "RFC 3986",
                section: Some("3"),
                url: "https://www.rfc-editor.org/rfc/rfc3986.html#section-3",
                note: "`URI` — the production `ext-rel-type` is, and the reason a relation type \
                       with a scheme is read as one instead of being measured against `tchar`. \
                       `URI-Reference` (§4.1) is the target's",
            },
            crate::rules::SpecRef {
                spec: "RFC 5646",
                section: Some("2.1"),
                url: "https://www.rfc-editor.org/rfc/rfc5646.html#section-2.1",
                note: "Syntax: `Language-Tag`, the whole of §3.4.1's ABNF for an `hreflang` \
                       value. What is enforced is the catalogue's shared conservative floor — \
                       subtag shape, from this section's prose — not the full grammar and not \
                       the registry",
            },
            crate::rules::SpecRef {
                spec: "RFC 6838",
                section: Some("4.2"),
                url: "https://www.rfc-editor.org/rfc/rfc6838.html#section-4.2",
                note: "Naming Requirements: `restricted-name`, the production behind both \
                       halves of a `type` value. It opens on a letter or digit and closes at \
                       127 characters, and §3.4.1's ABNF for the value ends at the \
                       subtype-name, so there is no parameters group and no wildcard here",
            },
            crate::rules::SpecRef {
                spec: "HTML Semantics",
                section: Some("4.2.4.4"),
                url:
                    "https://html.spec.whatwg.org/multipage/semantics.html#processing-link-headers",
                note: "*Processing `Link` headers* — the algorithm that reads this field out of a \
                       **response** and, for `rel=preload`, returns early when `as` does not \
                       exist. The only published sentence pairing the two, and the reason that \
                       finding is worded as a member being discarded rather than as a MUST",
            },
            crate::rules::SpecRef {
                spec: "HTML Links",
                section: Some("4.6.8.20"),
                url: "https://html.spec.whatwg.org/multipage/links.html#link-type-preload",
                note: "Where the `preload` keyword itself is defined, and where it says the \
                       resource is fetched *according to the preload destination given by the \
                       `as` attribute*. The old reference here named a retired W3C Preload \
                       specification in its note while pointing at this page",
            },
            crate::rules::SpecRef {
                spec: "RFC 8297",
                section: Some("2"),
                url: "https://www.rfc-editor.org/rfc/rfc8297.html#section-2",
                note: "Early Hints. Named because a check here used to be gated on the 103 status \
                       and rest on this document: it states nothing about a `Link` member's \
                       content, and its modals are addressed to the client",
            },
        ]
    }

    fn examples(&self) -> &'static [crate::rules::Example] {
        use crate::rules::{Compliance, Example};
        &[
            Example {
                compliance: Compliance::Compliant,
                label: Some("Response"),
                snippet: "HTTP/1.1 200 OK\nLink: <https://example.com/style.css>; rel=preload; as=style\nLink: <https://example.com/page2>; rel=\"next\"; title=\"Next page\"",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(an extension relation type is a URI — RFC 8288 §3.5's own example)"),
                snippet: "HTTP/1.1 200 OK\nLink: </>; rel=\"http://example.net/foo\"",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(the optional group makes a valueless parameter conforming)"),
                snippet: "HTTP/1.1 200 OK\nLink: <https://example.com/>; rel=next; nofollow",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(a comma inside the target is a sub-delim, not a separator)"),
                snippet: "HTTP/1.1 200 OK\nLink: </a,b>; rel=next, </c>; rel=prev",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("Request"),
                snippet: "POST /uploads HTTP/1.1\nHost: example.com\nLink: <https://example.com/types/photo>; rel=\"type\"",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(no angle brackets around the target)"),
                snippet: "HTTP/1.1 200 OK\nLink: https://example.com/style.css; rel=preload; as=style",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(§3.3 requires rel in every link-value)"),
                snippet: "HTTP/1.1 200 OK\nLink: <https://example.com/>; title=\"Home\"",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(neither a reg-rel-type nor an absolute URI)"),
                snippet: "HTTP/1.1 200 OK\nLink: <https://example.com/>; rel=Next",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(rel twice in one link-value)"),
                snippet: "HTTP/1.1 200 OK\nLink: <https://example.com/>; rel=next; rel=prev",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(BWS beside the \"=\")"),
                snippet: "HTTP/1.1 200 OK\nLink: <https://example.com/>; rel = next",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(the HTML processing model drops a preload with no as)"),
                snippet: "HTTP/1.1 103 Early Hints\nLink: <https://example.com/script.js>; rel=preload",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(an invalid character in a parameter name)"),
                snippet: "HTTP/1.1 200 OK\nLink: <https://example.com/>; rel=next; bad@=1",
            },
            Example {
                compliance: Compliance::Compliant,
                label: Some("(hreflang and type values, measured after unquoting)"),
                snippet: "HTTP/1.1 200 OK\nLink: <https://example.com/de>; rel=alternate; hreflang=de; type=\"text/html\"",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(an hreflang value that is not a Language-Tag)"),
                snippet: "HTTP/1.1 200 OK\nLink: <https://example.com/>; rel=alternate; hreflang=en_US",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: Some("(a type value with no subtype-name after a '/')"),
                snippet: "HTTP/1.1 200 OK\nLink: <https://example.com/>; rel=alternate; type=text",
            },
        ]
    }
}

/// Registers this rule into the engine's auto-collected catalogue.
#[linkme::distributed_slice(crate::rules::REGISTERED_RULES)]
static REGISTRATION: &dyn crate::rules::Rule = &MessageLinkHeaderValidity;

/// Judge one section's `Link`, if it carries one.
///
/// The field lines of a section are joined into the one list they are, over the
/// raw octets. Reading the value through `to_str` instead — which is what this
/// rule did — turned two different messages into one finding about encoding:
/// an octet at or above %x80 is a defect where it stands in a `token` or inside
/// the angle brackets, and it is ordinary `qdtext` inside a `quoted-string`,
/// which `title="caf\u{e9}"` is. Neither of those is *"the header contains a
/// non-UTF8 value"*, and one of them is not a finding at all.
fn judge(headers: &hyper::HeaderMap, side: &str, is_response: bool) -> Option<String> {
    let value = combined_field_value_as_written(headers, "link")?;

    validate_link(&value, is_response)
        .err()
        .map(|e| format!("{side} Link header: {e}"))
}

/// Validate a whole `Link` field value.
///
/// The first production is quoted with the line below it because
/// `Link = #link-value` is eighteen characters once whitespace is collapsed,
/// under the extractor's floor for a quote that is to be evidence of anything.
/// The neighbour it drags in is the member's own production, which is quoted on
/// its own where it decides something.
// cite(RFC 8288 § 1.2): "The requirements regarding conformance and error handling highlighted in [RFC7230], Section 2.5 apply to this document."
// cite(RFC 9110 § 2.2): "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules."
// cite(RFC 8288 § 3): "Link       = #link-value link-value = "<" URI-Reference ">" *( OWS ";" OWS link-param )"
fn validate_link(value: &str, is_response: bool) -> Result<(), String> {
    // cite(RFC 9110 § 5.5): "A field value does not include leading or trailing whitespace."
    let v = trim_ows(value);

    // `#` carries no minimum, so a field line with nothing in it declares no
    // link rather than declaring one badly. The check has to come before the
    // walk, because splitting an empty value yields one empty member and the
    // sentence below would report it.
    //
    // cite(RFC 9110 § 5.6.1.2): "#element => [ element ] *( OWS "," OWS [ element ] )"
    if v.is_empty() {
        return Ok(());
    }

    for (index, member) in split_link_values(v).into_iter().map(trim_ows).enumerate() {
        let n = index + 1;

        // cite(RFC 9110 § 5.6.1.1): "In any production that uses the list construct, a sender MUST NOT generate empty list elements."
        if member.is_empty() {
            return Err(format!(
                "member {n} is empty, and the list construct admits no empty element"
            ));
        }

        validate_link_value(member, is_response).map_err(|e| format!("member {n} {e}"))?;
    }

    Ok(())
}

/// Cut a `Link` field value at the commas that separate its members.
///
/// Two constructs in a `link-value` hold a comma as data, and the document says
/// so about both. A `URI-Reference` admits `,` as a `sub-delim`, so `</a,b>` is
/// one target; and §3.3 requires an extension relation type to be quoted
/// *"when they contain characters not allowed in tokens, such as a semicolon
/// (";") or comma (",") (as these characters are used as delimiters in the
/// header field itself)"*, which is the document naming the hazard. A plain
/// `split(',')` reported `Link: </a,b>; rel=next` as two malformed members and
/// found an *empty* member in `title="a,,b"`.
///
/// The angle brackets take precedence over the DQUOTE rather than nesting with
/// it: no `URI-Reference` admits a `"` at all, so a DQUOTE between `<` and `>`
/// is already the finding, and letting it flip quote parity would swallow every
/// later member into one.
///
/// A `<` opens the bracketed target wherever it stands rather than only at a
/// member's start, which costs one thing and it is worth naming: a value whose
/// first member is malformed in that particular way (`a<b, </c>; rel=next`)
/// comes back as one member instead of two. The member is a finding either way
/// and it is the finding reported; what the tolerance buys is a splitter that
/// does not have to know where a member begins.
///
/// **Written here rather than beside
/// [`split_commas_respecting_quotes`](crate::helpers::headers::split_commas_respecting_quotes),
/// and that is a decision rather than a deferral.** This is the only field in
/// the tree whose members are bracketed, and the one other value that carries a
/// bracketed sub-production — `From`, whose `mailbox` may take the `name-addr`
/// alternative and its `angle-addr` — cannot use a splitter at all. RFC 5322's
/// `comment` names itself, so the structure a comma can hide inside there is
/// balanced and recursive; `helpers::mailbox` steps over quoted strings,
/// comments and angle brackets with a real reader, and asking a flat
/// bracket-aware splitter for that answer would be a false-positive generator.
///
/// So the shared answer still moves on a second caller, and the candidate that
/// looked like one is the argument for keeping this private: **two productions
/// can both bracket something and still need different machines to read it.**
// cite(RFC 8288 § 3): "link-value = "<" URI-Reference ">" *( OWS ";" OWS link-param )"
// cite(RFC 3986 § 2.2): "sub-delims  = "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "=""
fn split_link_values(s: &str) -> Vec<&str> {
    let bytes = s.as_bytes();
    let mut res = Vec::new();
    let mut start = 0usize;
    let mut in_angle = false;
    let mut in_quote = false;
    let mut prev_backslash = false;

    for (i, &b) in bytes.iter().enumerate() {
        if in_angle {
            if b == b'>' {
                in_angle = false;
            }
            continue;
        }
        if prev_backslash {
            prev_backslash = false;
        // `quoted-pair` is defined as part of `quoted-string` and nowhere else,
        // so outside one a backslash is an ordinary octet.
        // cite(RFC 9110 § 5.6.4): "quoted-pair    = "\" ( HTAB / SP / VCHAR / obs-text )"
        } else if b == b'\\' && in_quote {
            prev_backslash = true;
        } else if b == b'"' {
            in_quote = !in_quote;
        } else if b == b'<' && !in_quote {
            in_angle = true;
        } else if b == b',' && !in_quote {
            res.push(&s[start..i]);
            start = i + 1;
        }
    }
    res.push(&s[start..]);
    res
}

/// The `link-param` names this serialisation bounds to one occurrence in a
/// `link-value`, each in its own MUST NOT.
///
/// §3.3's sentence is quoted here for its second clause only — `rel`'s presence
/// is [`missing_rel`]'s half of the same sentence, and neither site enforces the
/// other's.
///
/// `hreflang` is the row that is deliberately absent, and it is what shows the
/// table was read rather than assumed: §3.4.1 gives repeating it a *meaning* —
/// *"Multiple hreflang attributes on a single link-value indicate that multiple
/// languages are available from the indicated resource."* — so bounding it
/// would report a conforming member for saying something true. `anchor` is
/// absent for the plainer reason that §3.2 states no such sentence about it.
///
/// Compared case-insensitively, which is §2.2's requirement about the names of
/// target attributes rather than a convenience.
// cite(RFC 8288 § 3.3): "The rel parameter MUST be present but MUST NOT appear more than once in a given link-value; occurrences after the first MUST be ignored by parsers."
// cite(RFC 8288 § 3.4.1): "There MUST NOT be more than one media attribute in a link-value; occurrences after the first MUST be ignored by parsers."
// cite(RFC 8288 § 3.4.1): "The title attribute MUST NOT appear more than once in a given link; occurrences after the first MUST be ignored by parsers."
// cite(RFC 8288 § 3.4.1): "The title* link-param MUST NOT appear more than once in a given link-value; occurrences after the first MUST be ignored by parsers."
// cite(RFC 8288 § 3.4.1): "The type attribute MUST NOT appear more than once in a given link-value; occurrences after the first MUST be ignored by parsers."
const AT_MOST_ONCE: &[&str] = &["rel", "media", "title", "title*", "type"];

/// Validate one `link-value`.
// cite(RFC 8288 § 3): "link-value = "<" URI-Reference ">" *( OWS ";" OWS link-param )"
fn validate_link_value(member: &str, is_response: bool) -> Result<(), String> {
    let Some(rest) = member.strip_prefix('<') else {
        return Err(format!(
            "'{}' does not open with the '<' the production prints before its URI-Reference",
            shown_in_finding(member)
        ));
    };

    // `<` and `>` are neither of them URI characters, so the first `>` is the
    // one that closes the target -- there is no component of a `URI-Reference`
    // it could be sitting inside.
    let Some(close) = rest.find('>') else {
        return Err(format!(
            "'{}' has no '>' closing its URI-Reference",
            shown_in_finding(member)
        ));
    };
    let (target, after) = rest.split_at(close);

    // The target is a URI, converted from an IRI by the sender if it began as
    // one. That conversion is what makes an octet outside the URI alphabet a
    // finding here rather than a question about the field's encoding: %xE9 in
    // the brackets is an IRI that was never converted.
    //
    // The empty target is not one of these: `URI-Reference` derives the empty
    // string (a `relative-ref` with an empty `path-abempty`), and `<>` names
    // the message's own context.
    // cite(RFC 8288 § 3.1): "Each link-value conveys one target IRI as a URI-Reference (after conversion to one, if necessary; see [RFC3987], Section 3.1) inside angle brackets ("<>")."
    if let Some(c) = find_non_uri_char(target) {
        return Err(format!(
            "target '{}' holds {}, which no URI-Reference admits",
            shown_in_finding(target),
            describe_char(c)
        ));
    }

    // `*( OWS ";" OWS link-param )` -- the repetition opens on a `;` and there
    // is no bracket around `link-param` inside it, so every `;` owes a
    // parameter and anything else after the `>` derives from nothing. `Prefer`
    // writes `*( OWS ";" [ OWS parameter ] )` and its bare `;` is conforming
    // for exactly the bracket this production does not have.
    let after = trim_ows(&after[1..]);
    if after.is_empty() {
        return missing_rel(member);
    }
    let Some(params_src) = after.strip_prefix(';') else {
        return Err(format!(
            "'{}' has '{}' after its '>', where the production admits only ';'-delimited parameters",
            shown_in_finding(member),
            shown_in_finding(after)
        ));
    };

    let mut seen: Vec<String> = Vec::new();
    let mut rel_value: Option<String> = None;

    for segment in split_semicolons_respecting_quotes(params_src) {
        if segment.is_empty() {
            return Err(format!(
                "'{}' has a ';' with no link-param after it",
                shown_in_finding(member)
            ));
        }

        // cite(RFC 8288 § 3): "link-param = token BWS [ "=" BWS ( token / quoted-string ) ]"
        // cite(RFC 8288 § 3): "Note that any link-param can be generated with values using either the token or the quoted-string syntax; therefore, recipients MUST be able to parse both forms."
        // cite(RFC 8288 § 3): "Individual link-params specify their syntax in terms of the value after any necessary unquoting"
        // cite(RFC 8288 § 1.1): "This document uses the Augmented Backus-Naur Form (ABNF) [RFC5234] notation of [RFC7230], including the #rule, and explicitly includes the following rules from it"
        let parsed = parse_token_bws_word(segment).map_err(|e| {
            format!(
                "parameter '{}' does not match link-param: {}",
                shown_in_finding(segment),
                e
            )
        })?;

        // The `BWS` is printed in this production, so the trim above is what a
        // recipient is required to do -- and the sender is required not to have
        // written the whitespace at all. Both halves are in the same paragraph,
        // and the second one had nothing looking at it here.
        //
        // cite(RFC 9110 § 5.6.3): "A sender MUST NOT generate BWS in messages."
        // cite(RFC 9110 § 5.6.3): "A recipient MUST parse for such bad whitespace and remove it before interpreting the protocol element."
        if parsed.bws {
            return Err(format!(
                "parameter '{}' has whitespace around its '='; the grammar admits BWS there only for historical reasons",
                shown_in_finding(segment)
            ));
        }

        // cite(RFC 8288 § 2.2): "The names of target attributes SHOULD conform to the token rule, but SHOULD NOT include any of the characters "%", "'", or "*", for portability across serialisations and MUST be compared in a case-insensitive fashion."
        let name = parsed.name.to_ascii_lowercase();

        if AT_MOST_ONCE.contains(&name.as_str()) && seen.contains(&name) {
            return Err(format!(
                "writes '{}' more than once, and this serialisation admits it at most once in a link-value",
                parsed.name
            ));
        }
        match name.as_str() {
            "rel" => {
                // A `rel` with no `=` and a `rel=""` are the same statement
                // here: the optional group makes the first derive from
                // `link-param`, and §3.3's own ABNF for the value then asks it
                // for a `relation-type` that neither of them has.
                rel_value = Some(parsed.value.unwrap_or_default());
            }
            // §3.4.1 prints `Language-Tag` as the whole of this value's ABNF.
            // §1.1's second import list is where the production comes from,
            // and that list is quotable only up to its reference brackets —
            // each `[RFCxxxx]` is an anchor the extractor cuts the passage at
            // — so the sentence introducing the ABNF is the evidence here and
            // the import is named in `specifications()`. The validator is the
            // catalogue's shared conservative floor for RFC 5646 § 2.1, the
            // same reader `Content-Language`'s rule uses: subtag shape, not
            // the full grammar and not the registry, with the sentences it
            // does enforce quoted at the helper.
            //
            // A valueless `hreflang` and an `hreflang=""` both arrive as the
            // empty string and fail the way `rel=` does: the production is
            // the value's whole grammar, and there is no value. Every
            // occurrence is judged, because repeating this attribute is
            // §3.4.1's own way of saying several languages are available, and
            // each repetition still owes the production.
            // cite(RFC 8288 § 3.4.1): "The ABNF for the hreflang parameter's value is:"
            "hreflang" => {
                let value = parsed.value.as_deref().unwrap_or_default();
                if let Err(why) = crate::helpers::language::validate_language_tag(value) {
                    return Err(format!(
                        "writes hreflang='{}', which does not derive from Language-Tag: {}",
                        shown_in_finding(value),
                        why
                    ));
                }
            }
            // cite(RFC 8288 § 3.4.1): "The ABNF for the type parameter's value is:"
            "type" => {
                let value = parsed.value.as_deref().unwrap_or_default();
                if let Err(why) = type_value_defect(value) {
                    return Err(format!(
                        "writes type='{}', which does not derive from type-name \"/\" subtype-name: {}",
                        shown_in_finding(value),
                        why
                    ));
                }
            }
            // `media` is the one §3.4.1 value grammar this catalogue does not
            // read, and the decline is published in `description()`: §1.1
            // imports `media-query-list` from the dated 2012 CSS3 Media
            // Queries Recommendation — a grammar in CSS's formalism rather
            // than ABNF, from a document `sources.yaml` does not carry. The
            // section's one MUST about the value is unobservable here besides:
            // an unquoted ';' or ',' is this field's own delimiter, so the
            // parse that could ask the question is the parse that already cut
            // the value apart and reported the pieces.
            // cite(RFC 8288 § 3.4.1): "The ABNF for the media parameter's value is:"
            // cite(RFC 8288 § 3.4.1): "Its value MUST be quoted if it contains a semicolon (";") or comma (",")."
            "media" => {}
            _ => {}
        }
        seen.push(name);
    }

    let Some(rel_value) = rel_value else {
        return missing_rel(member);
    };

    let relation_types = validate_rel_value(&rel_value)?;

    // The fold cannot change an answer today, and that is worth saying rather
    // than leaving for a reader to trace: every relation type reaching here
    // derives from `reg-rel-type`, which admits no capital, or from
    // `ext-rel-type`, which needs a scheme -- so `PreLoad` was already reported
    // one function up, against the grammar, and never gets this far. The fold
    // is kept because the requirement is the document's and not an invariant of
    // the code above it; a `==` here would silently become case-sensitive the
    // day that alternation is loosened.
    //
    // cite(RFC 8288 § 2.1.1): "Registered relation type names MUST conform to the reg-rel-type rule (see Section 3.3) and MUST be compared character by character in a case-insensitive fashion."
    let preloads = relation_types
        .iter()
        .any(|t| t.eq_ignore_ascii_case("preload"));

    // The only published sentence pairing `preload` with `as` is a step of the
    // HTML Standard's algorithm for reading this field out of a *response*, and
    // what it does is stop -- the member never becomes a preload at all. That
    // is why this is gated on the direction and why the finding says the member
    // was discarded rather than that a requirement was broken: no RFC states
    // one, and HTML's own `must` about `as` is authoring conformance for a
    // `link` element rather than for a field.
    //
    // cite(HTML Semantics): "To process link headers given a Document doc, a response response, and a "pre-media" or "media" phase"
    // cite(HTML Semantics): "Apply link options from parsed header attributes to options given attribs"
    // cite(HTML Semantics): "If attribs["as"] does not exist, then return false."
    if is_response && preloads && !seen.iter().any(|n| n == "as") {
        return Err(format!(
            "'{}' asks for a preload with no 'as' parameter, so the HTML processing model for a response's Link headers stops before fetching anything",
            shown_in_finding(member)
        ));
    }

    Ok(())
}

/// The `rel` requirement, written once for the two branches that reach it — a
/// member with no parameters at all, and a member whose parameters do not
/// include this one. Quoted for its first clause; the second is
/// [`AT_MOST_ONCE`]'s.
// cite(RFC 8288 § 3.3): "The relation type of a link conveyed in the Link header field is conveyed in the "rel" parameter's value."
// cite(RFC 8288 § 3.3): "The rel parameter MUST be present but MUST NOT appear more than once in a given link-value; occurrences after the first MUST be ignored by parsers."
fn missing_rel(member: &str) -> Result<(), String> {
    Err(format!(
        "'{}' carries no 'rel' parameter, and a link-value must have one",
        shown_in_finding(member)
    ))
}

/// Split a `rel` value into its relation types and judge each one.
///
/// The separator is `1*SP` and nothing else: a `split_whitespace` here would
/// take a HTAB inside a `quoted-string` for a separator, and HTAB is `qdtext` a
/// sender wrote *inside* a relation type. Repeated spaces are one separator
/// because the quantifier says so; a leading or trailing one is not admitted at
/// all, because the production opens and closes on a `relation-type`.
// cite(RFC 8288 § 3.3): "relation-type *( 1*SP relation-type )"
// cite(RFC 8288 § 3.3): "The rel parameter can, however, contain multiple link relation types."
fn validate_rel_value(value: &str) -> Result<Vec<&str>, String> {
    if value.is_empty() {
        return Err(
            "writes 'rel' with no value, where §3.3 asks it for one or more relation types".into(),
        );
    }
    if value.starts_with(' ') || value.ends_with(' ') {
        return Err(format!(
            "writes rel='{}', which opens or closes on a space the production does not admit",
            shown_in_finding(value)
        ));
    }

    let types: Vec<&str> = value.split(' ').filter(|t| !t.is_empty()).collect();
    for t in &types {
        relation_type_defect(t)?;
    }
    Ok(types)
}

/// Whether one relation type derives from either of the two alternatives.
///
/// The alternation is the whole of the check, and reading only one half of it
/// is what a `tchar` scan here was doing in both directions at once:
/// `reg-rel-type` admits *less* than a `token` (no capital, no `_`, no `!`) and
/// `ext-rel-type` admits far more, since a URI holds `:` and `/`. So a scan
/// against `tchar` passed `Next` — which is neither — and reported
/// `http://example.net/foo`, which §3.5 prints as an example of a conforming
/// field.
///
/// The URI half is tested by its scheme rather than parsed: §3.3 requires an
/// extension relation type to be an *absolute* URI, and a scheme is the one
/// component `relation-type`'s other alternative can never have, since
/// `reg-rel-type` admits no `:`.
// cite(RFC 8288 § 3.3): "relation-type  = reg-rel-type / ext-rel-type"
// cite(RFC 8288 § 3.3): "reg-rel-type   = LOALPHA *( LOALPHA / DIGIT / "." / "-" )"
// cite(RFC 8288 § 3.3): "ext-rel-type   = URI ; Section 3 of [RFC3986]"
// cite(RFC 8288 § 3.3): "Note that extension relation types are REQUIRED to be absolute URIs in Link header fields and MUST be quoted when they contain characters not allowed in tokens"
// cite(RFC 8288 § 2.1.2): "When extension relation types are compared, they MUST be compared as strings (after converting to URIs if serialised in a different format) in a case-insensitive fashion, character by character."
fn relation_type_defect(t: &str) -> Result<(), String> {
    if is_reg_rel_type(t) {
        return Ok(());
    }

    // A scheme is delimited by the first `:`, and only when nothing before it
    // opens another component. `reg-rel-type` has none of those characters
    // either, so reaching here without a scheme means the value derives from
    // neither alternative.
    // cite(RFC 3986 § 3.1): "scheme      = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )"
    let first_component = &t[..t.find(['/', '?', '#']).unwrap_or(t.len())];
    let scheme_defect = match first_component.find(':') {
        Some(colon) => validate_scheme_name(&t[..colon]).err(),
        None => Some("it has no scheme".to_string()),
    };

    if let Some(why) = scheme_defect {
        return Err(format!(
            "names the relation type '{}', which is not a reg-rel-type (a lowercase letter, then lowercase letters, digits, '.' and '-') and is not an absolute URI either: {}",
            shown_in_finding(t),
            why
        ));
    }

    if let Some(c) = find_non_uri_char(t) {
        return Err(format!(
            "names the extension relation type '{}', which holds {} and so is not a URI",
            shown_in_finding(t),
            describe_char(c)
        ));
    }

    Ok(())
}

/// `reg-rel-type = LOALPHA *( LOALPHA / DIGIT / "." / "-" )`.
///
/// `LOALPHA` is imported from RFC 7230's notation by §1.1 and is `%x61-7A` —
/// lowercase only. That is narrower than `token` and it is the point of the
/// production: §2.1.1 makes registered names conform to this rule, and the
/// case-insensitive comparison it requires alongside is about *reading* a name,
/// not about what a sender may write.
// cite(RFC 8288 § 3.3): "reg-rel-type   = LOALPHA *( LOALPHA / DIGIT / "." / "-" )"
fn is_reg_rel_type(t: &str) -> bool {
    let mut chars = t.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_lowercase() {
        return false;
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-')
}

/// Whether a `type` attribute's value derives from `type-name "/" subtype-name`.
///
/// The production is the whole of §3.4.1's ABNF for this value, so it ends at
/// the subtype-name: there is no `parameters` group here, and a `;` after the
/// subtype is an octet `restricted-name-chars` does not admit rather than the
/// start of a `charset`. That is why the reader is not
/// [`crate::helpers::headers::parse_media_type`] — that function implements
/// RFC 9110 § 8.3.1's `media-type`, whose halves are `token` and whose tail
/// admits parameters, and both answers are wrong here: `restricted-name` is
/// narrower than `token` (it opens on a letter or digit, so `*/*` derives from
/// nothing), and this value has no parameters to admit.
// cite(RFC 6838 § 4.2): "type-name = restricted-name subtype-name = restricted-name"
fn type_value_defect(value: &str) -> Result<(), String> {
    let Some((type_name, subtype_name)) = value.split_once('/') else {
        return Err("it has no '/' between a type-name and a subtype-name".into());
    };
    restricted_name_defect(type_name, "type-name")?;
    restricted_name_defect(subtype_name, "subtype-name")?;
    Ok(())
}

/// `restricted-name = restricted-name-first *126restricted-name-chars`.
///
/// First transcription of this production in the tree, and it stays private
/// until a second caller arrives asking the same question. The two rules that
/// read RFC 6838 § 4.2 before this one deliberately measured `token` instead —
/// subtype *spelling* was a neighbour's question there, and the neighbour's
/// grammar really is `token` — where here the spelling is the whole question,
/// because §3.4.1 names this document's production and not RFC 9110's.
///
/// The `.` and `+` alternatives are quoted with the trailing comments the
/// document prints on them; what the comments assign those characters — facet
/// names, structured-syntax suffixes — is the neighbouring suffix rule's
/// question, not this one's, so they are admitted here and read nowhere.
// cite(RFC 6838 § 4.2): "Type and subtype names MUST conform to the following ABNF:"
// cite(RFC 6838 § 4.2): "restricted-name = restricted-name-first *126restricted-name-chars restricted-name-first  = ALPHA / DIGIT"
// cite(RFC 6838 § 4.2): "restricted-name-chars = ALPHA / DIGIT / "!" / "#" / "$" / "&" / "-" / "^" / "_""
// cite(RFC 6838 § 4.2): "restricted-name-chars =/ "." ; Characters before first dot always ; specify a facet name"
// cite(RFC 6838 § 4.2): "restricted-name-chars =/ "+" ; Characters after last plus always ; specify a structured syntax suffix"
fn restricted_name_defect(name: &str, half: &str) -> Result<(), String> {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return Err(format!("its {half} is empty"));
    };
    if !first.is_ascii_alphanumeric() {
        return Err(format!(
            "its {half} opens on {}, where restricted-name-first admits a letter or digit",
            describe_char(first)
        ));
    }
    if let Some(c) = chars.find(|&c| {
        !(c.is_ascii_alphanumeric()
            || matches!(c, '!' | '#' | '$' | '&' | '-' | '^' | '_' | '.' | '+'))
    }) {
        return Err(format!(
            "its {half} holds {}, which restricted-name-chars does not admit",
            describe_char(c)
        ));
    }
    // `restricted-name-first *126restricted-name-chars` closes at 127. Byte
    // length is character length by this line: everything the two checks
    // above admit is ASCII.
    if name.len() > 127 {
        return Err(format!(
            "its {half} is {} characters long, where the production admits at most 127",
            name.len()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// Fixtures are octets rather than `&str` throughout, because two of the
    /// grammars this rule reads disagree about the octets above %x7E: `qdtext`
    /// admits `obs-text` and `token` and `URI-Reference` do not, and
    /// `HeaderValue::from_str` cannot express one at all. A `&str` fixture
    /// would have been unable to state either half of that.
    fn cfg() -> crate::config::Config {
        crate::test_helpers::make_test_config_with_enabled_rules(&["message_link_header_validity"])
    }

    fn run(tx: &crate::http_transaction::HttpTransaction) -> Option<String> {
        MessageLinkHeaderValidity
            .check_transaction(
                tx,
                &crate::transaction_history::TransactionHistory::empty(),
                &cfg(),
            )
            .map(|v| v.message)
    }

    fn judge_response(status: u16, value: &[u8]) -> Option<String> {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(status, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_octet_pairs(&[("Link", value)]);
        run(&tx)
    }

    fn judge_request(value: &[u8]) -> Option<String> {
        let mut tx = crate::test_helpers::make_test_transaction();
        tx.request.headers = crate::test_helpers::make_headers_from_octet_pairs(&[("Link", value)]);
        run(&tx)
    }

    #[rstest]
    // The grammar, member by member.
    #[case(b"<https://example.com/>; rel=next")]
    #[case(b"<>; rel=next")]
    #[case(b"<https://example.com/>; rel=\"next\"; title=\"Home\"")]
    #[case(b"<https://example.com/>; rel=next; title=\"a;b\"")]
    // RFC 8288 § 3.5's own examples, run as the document prints them.
    #[case(b"</>; rel=\"http://example.net/foo\"")]
    #[case(b"<http://example.org/>; rel=\"start http://example.net/relation/other\"")]
    #[case(b"<http://example.com/TheBook/chapter2>; rel=\"previous\"; title=\"previous chapter\"")]
    #[case(b"</terms>; rel=\"copyright\"; anchor=\"#foo\"")]
    #[case(b"</TheBook/chapter2>; rel=\"previous\"; title*=UTF-8'de'letztes%20Kapitel, </TheBook/chapter4>; rel=\"next\"; title*=UTF-8'de'n%c3%a4chstes%20Kapitel")]
    #[case(b"<https://example.org/>; rel=\"start\", <https://example.org/index>; rel=\"index\"")]
    // The optional group: a link-param may carry no value at all.
    #[case(b"<https://example.com/>; rel=next; nofollow")]
    // A comma is data inside the target and inside a quoted-string.
    #[case(b"</a,b>; rel=next")]
    #[case(b"<https://example.com/>; rel=next; title=\"a,,b\"")]
    // `#` has no minimum, so an empty field value declares no link.
    #[case(b"")]
    // Repeating hreflang is what § 3.4.1 says several languages look like.
    #[case(b"<https://example.com/>; rel=alternate; hreflang=en; hreflang=de")]
    // The two § 3.4.1 value grammars measured here, in both spellings of the
    // word: a token and a quoted-string are the same value after unquoting.
    #[case(b"<https://example.com/de>; rel=alternate; hreflang=de; type=\"text/html\"")]
    #[case(b"<https://example.com/>; rel=alternate; hreflang=\"zh-Hant\"")]
    // `.` and `+` are restricted-name-chars; what they mean is the suffix
    // rule's question, not this one's.
    #[case(b"<https://example.com/>; rel=alternate; type=\"application/vnd.api+json\"")]
    // %xE9 inside a quoted-string is `qdtext`, and reading the field through
    // `to_str` used to report the whole message for it.
    #[case(b"<https://example.com/>; rel=next; title=\"caf\xe9\"")]
    fn conforming_values_draw_nothing(#[case] value: &[u8]) {
        assert_eq!(
            judge_response(200, value),
            None,
            "value: {}",
            String::from_utf8_lossy(value)
        );
    }

    /// Exact messages, not substrings: a finding here is assembled in three
    /// functions — the side, the member index, and the clause — and a test
    /// asserting only that a violation exists cannot see the prefix and the
    /// verb phrase disagree. One case per branch that emits.
    #[rstest]
    #[case(
        b"https://example/; rel=next",
        "member 1 'https://example/; rel=next' does not open with the '<' the production prints before its URI-Reference"
    )]
    #[case(
        b"<https://example/; rel=next",
        "member 1 '<https://example/; rel=next' has no '>' closing its URI-Reference"
    )]
    #[case(
        b"</a\xe9>; rel=next",
        "member 1 target '/a\u{e9}' holds 0xE9, which no URI-Reference admits"
    )]
    #[case(
        b"</a> junk; rel=next",
        "member 1 '</a> junk; rel=next' has 'junk; rel=next' after its '>', where the production admits only ';'-delimited parameters"
    )]
    #[case(
        b"</a>; rel=next;",
        "member 1 '</a>; rel=next;' has a ';' with no link-param after it"
    )]
    #[case(
        b"</a>; bad@=1; rel=next",
        "member 1 parameter 'bad@=1' does not match link-param: token contains '@'"
    )]
    #[case(
        b"</a>; rel = next",
        "member 1 parameter 'rel = next' has whitespace around its '='; the grammar admits BWS there only for historical reasons"
    )]
    #[case(
        b"</a>; rel=next; rel=prev",
        "member 1 writes 'rel' more than once, and this serialisation admits it at most once in a link-value"
    )]
    #[case(
        b"</a>; rel=next; title=a; title=b",
        "member 1 writes 'title' more than once, and this serialisation admits it at most once in a link-value"
    )]
    #[case(
        b"</a>",
        "member 1 '</a>' carries no 'rel' parameter, and a link-value must have one"
    )]
    #[case(
        b"</a>; title=\"Home\"",
        "member 1 '</a>; title=\\\"Home\\\"' carries no 'rel' parameter, and a link-value must have one"
    )]
    #[case(
        b"</a>; rel",
        "member 1 writes 'rel' with no value, where \u{a7}3.3 asks it for one or more relation types"
    )]
    #[case(
        b"</a>; rel=\" next\"",
        "member 1 writes rel=' next', which opens or closes on a space the production does not admit"
    )]
    #[case(
        b"</a>; rel=Next",
        "member 1 names the relation type 'Next', which is not a reg-rel-type (a lowercase letter, then lowercase letters, digits, '.' and '-') and is not an absolute URI either: it has no scheme"
    )]
    #[case(
        b"</a>; rel=\"9x:/b\"",
        "member 1 names the relation type '9x:/b', which is not a reg-rel-type (a lowercase letter, then lowercase letters, digits, '.' and '-') and is not an absolute URI either: scheme '9x' must begin with a letter"
    )]
    // A URI holds no SP, so `1*SP` cuts this into two relation types and the
    // first of them is a conforming absolute URI. The finding is the second.
    #[case(
        b"</a>; rel=\"http://a b/\"",
        "member 1 names the relation type 'b/', which is not a reg-rel-type (a lowercase letter, then lowercase letters, digits, '.' and '-') and is not an absolute URI either: it has no scheme"
    )]
    #[case(
        b"</a>; rel=next, ,</b>; rel=prev",
        "member 2 is empty, and the list construct admits no empty element"
    )]
    #[case(
        b"</a>; rel=alternate; hreflang=en_US",
        "member 1 writes hreflang='en_US', which does not derive from Language-Tag: invalid character '_' in language tag"
    )]
    // A valueless hreflang reaches the validator as the empty string, the way
    // `rel` with no `=` does: the production is the value's whole grammar.
    #[case(
        b"</a>; rel=alternate; hreflang",
        "member 1 writes hreflang='', which does not derive from Language-Tag: empty language tag"
    )]
    #[case(
        b"</a>; rel=alternate; type=text",
        "member 1 writes type='text', which does not derive from type-name \"/\" subtype-name: it has no '/' between a type-name and a subtype-name"
    )]
    // `restricted-name-first` admits no asterisk, so the range every Accept
    // rule tolerates derives from nothing here.
    #[case(
        b"</a>; rel=alternate; type=\"*/*\"",
        "member 1 writes type='*/*', which does not derive from type-name \"/\" subtype-name: its type-name opens on '*', where restricted-name-first admits a letter or digit"
    )]
    // § 3.4.1's ABNF for the value ends at the subtype-name: there is no
    // parameters group, so the `;` is an inadmissible octet, not a charset.
    #[case(
        b"</a>; rel=alternate; type=\"text/html;charset=utf-8\"",
        "member 1 writes type='text/html;charset=utf-8', which does not derive from type-name \"/\" subtype-name: its subtype-name holds ';', which restricted-name-chars does not admit"
    )]
    #[case(
        b"</a>; rel=alternate; type=\"text/\"",
        "member 1 writes type='text/', which does not derive from type-name \"/\" subtype-name: its subtype-name is empty"
    )]
    fn every_branch_states_its_own_finding(#[case] value: &[u8], #[case] expected: &str) {
        assert_eq!(
            judge_response(200, value),
            Some(format!("Response Link header: {expected}"))
        );
    }

    /// The two branches whose message comes back out of a shared helper, kept
    /// apart from the table above because what they pin is the helper's wording
    /// reaching this rule's prefix intact.
    #[rstest]
    #[case(b"</a>; rel=", "nothing after the \"=\", where the grammar has a word")]
    #[case(b"</a>; rel=n\xe9xt", "value contains 0xE9")]
    // The DQUOTE the value opens with is escaped on its way into the finding —
    // it is the character being reported, and unescaped it reads as the message
    // quoting something.
    #[case(
        b"</a>; rel=next; title=\"unterminated",
        "Quoted-string not properly quoted: '\\\"unterminated'"
    )]
    fn link_param_defects_carry_the_shared_parsers_reason(
        #[case] value: &[u8],
        #[case] reason: &str,
    ) {
        let msg = judge_response(200, value).expect("reported");
        assert!(
            msg.contains("does not match link-param:") && msg.ends_with(reason),
            "{msg}"
        );
    }

    /// The finding this field's own document does not state, and the only one
    /// here with a direction. HTML's algorithm reads a *response*'s header
    /// list, so the same member in a request is not reported.
    #[test]
    fn preload_without_as_is_a_response_finding_only() {
        let value = b"<https://example.com/script.js>; rel=preload";
        let msg = judge_response(103, value).expect("a response preload with no as is reported");
        assert_eq!(
            msg,
            "Response Link header: member 1 '<https://example.com/script.js>; rel=preload' asks \
             for a preload with no 'as' parameter, so the HTML processing model for a response's \
             Link headers stops before fetching anything"
        );

        assert_eq!(judge_request(value), None);

        // The same member with `as` is clean, and the status is not the gate:
        // a 200 carrying the field is read exactly as the 103 is.
        assert_eq!(
            judge_response(
                103,
                b"<https://example.com/script.js>; rel=preload; as=script"
            ),
            None
        );
        assert!(judge_response(200, b"<https://a/>; rel=preload").is_some());

        // § 2.1.1 folds case when comparing a registered relation type, so the
        // keyword is recognised however it was written — and the spelling that
        // derives from neither production is a different finding.
        assert!(judge_response(200, b"<https://a/>; rel=preload; as=script").is_none());
        let msg =
            judge_response(200, b"<https://a/>; rel=\"PreLoad\"; as=script").expect("reported");
        assert!(msg.contains("is not a reg-rel-type"), "{msg}");
    }

    /// A request's `Link` reaches the grammar at all. The gate this replaces
    /// was a comment claiming the field is meaningful only on a response, and
    /// every finding here drew nothing from any of the 184 while it stood.
    #[test]
    fn a_requests_link_is_read() {
        assert_eq!(
            judge_request(b"<https://example.com/t>; rel=\"type\""),
            None
        );
        let msg = judge_request(b"https://example.com/t; rel=\"type\"").expect("reported");
        assert!(msg.starts_with("Request Link header:"), "{msg}");
    }

    /// The field lines of one section are one list, and a defect in the second
    /// line is a defect of the field.
    #[test]
    fn repeated_field_lines_are_one_list() {
        let mut tx = crate::test_helpers::make_test_transaction_with_response(200, &[]);
        tx.response.as_mut().unwrap().headers =
            crate::test_helpers::make_headers_from_octet_pairs(&[
                ("Link", b"<https://ok/>; rel=next"),
                ("Link", b"<https://bad/>; rel=Next"),
            ]);
        let msg = run(&tx).expect("reported");
        assert!(msg.contains("member 2"), "{msg}");
    }

    /// The `>` and the DQUOTE do not nest, and a comma inside either is data.
    /// Asserted on the splitter directly: a message naming "member 2" is what
    /// the member count would otherwise be inferred from, and the whole point
    /// of these cases is that there is no member 2.
    #[test]
    fn members_are_cut_outside_brackets_and_quotes() {
        assert_eq!(
            split_link_values("</a,b>; rel=next"),
            vec!["</a,b>; rel=next"]
        );
        assert_eq!(
            split_link_values("</a>; title=\"x,y\", </b>"),
            vec!["</a>; title=\"x,y\"", " </b>"]
        );
        assert_eq!(split_link_values("</a>, </b>"), vec!["</a>", " </b>"]);
        // A DQUOTE inside the brackets is the finding, not a quote: letting it
        // flip parity would swallow every later member into one.
        assert_eq!(split_link_values("</a\">, </b>"), vec!["</a\">", " </b>"]);
    }

    /// `reg-rel-type` is narrower than `token` and `ext-rel-type` is wider, so
    /// the alternation is not a character-class scan in either direction.
    #[rstest]
    #[case("next", true)]
    #[case("edit-media", true)]
    #[case("version.history", true)]
    #[case("a1", true)]
    #[case("Next", false)]
    #[case("a_b", false)]
    #[case("1a", false)]
    #[case("", false)]
    fn reg_rel_type_is_lowercase_only(#[case] t: &str, #[case] expected: bool) {
        assert_eq!(is_reg_rel_type(t), expected, "{t}");
    }

    /// `restricted-name-first *126restricted-name-chars` — the bound is 127,
    /// counted per half, and the first character is held to the narrower rule.
    #[test]
    fn restricted_name_closes_at_127_characters() {
        let ok = "a".repeat(127);
        assert!(type_value_defect(&format!("{ok}/{ok}")).is_ok());

        let long = "a".repeat(128);
        let err = type_value_defect(&format!("{long}/html")).unwrap_err();
        assert_eq!(
            err,
            "its type-name is 128 characters long, where the production admits at most 127"
        );

        // The first character answers to `restricted-name-first`, so a digit
        // conforms where a hyphen does not — even though both are
        // `restricted-name-chars`.
        assert!(type_value_defect("3gpp/vnd.x").is_ok());
        assert_eq!(
            type_value_defect("-a/b").unwrap_err(),
            "its type-name opens on '-', where restricted-name-first admits a letter or digit"
        );
        assert_eq!(
            type_value_defect("a/").unwrap_err(),
            "its subtype-name is empty"
        );
    }

    #[test]
    fn no_link_header_draws_nothing() {
        let tx = crate::test_helpers::make_test_transaction();
        assert!(run(&tx).is_none());
    }

    #[test]
    fn scope_is_both() {
        assert_eq!(
            MessageLinkHeaderValidity.scope(),
            crate::rules::RuleScope::Both
        );
    }

    #[test]
    fn validate_rules_with_valid_config() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        crate::test_helpers::enable_rule(&mut cfg, "message_link_header_validity");
        crate::rules::validate_rules(&cfg)?;
        Ok(())
    }
}
