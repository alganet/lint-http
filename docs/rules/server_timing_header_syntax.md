<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Server Server-Timing Header Syntax

## Description

Checks that a `Server-Timing` response field derives from the grammar the Server Timing specification prints in § 2: `Server-Timing = #server-timing-metric`, each metric a `metric-name` (a `token`) followed by `*( OWS ";" OWS server-timing-param )`, each parameter a `token` name, an `=` with `OWS` either side, and a value that is a `token` or a `quoted-string`.

**The requirement is RFC 9110 § 2.2's, not this document's.** The Server Timing specification holds nine BCP 14 keywords. Seven are addressed to the *user agent*: it MUST process and expose repeated metric names, it MAY surface them in any order, it MUST ignore a parameter name it does not recognise, it MUST ignore every occurrence of a repeated parameter after the first, it MUST ignore extraneous characters in two named places — all without signalling an error — and § 4 lets it MAY keep the same-origin restriction anyway. The eighth is a MAY permitting a response to repeat a metric name. Exactly one measures what a server wrote, and it is the SHOULD NOT below. So a rule that reports a server has to reach out of the document for its modal, and "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules" is it. A recipient being told to tolerate something is not the sender being told it may write it.

**A `quoted-string` may hold a comma and a semicolon, and both are separators here.** `Server-Timing: cache;desc="Cache Read, DB"` is one metric with one parameter. This rule splits both levels quote-aware; the value used to be split on bare `,` and `;`, which reported that field for an unterminated `quoted-string` it does not have.

**The one sentence the document does address to the field's content is reported.** "To avoid any possible ambiguity, individual server-timing-param-names SHOULD NOT appear multiple times within a server-timing-metric." A repeated parameter name is a finding, and it is the only advice-shaped one that comes from this document rather than from the grammar. The rule used to implement the user agent's *ignore the rest* MUST as its own silence, which made the SHOULD NOT the one thing in the document nothing enforced.

**Both field sections are read.** The specification's only worked exchange announces `Trailer: Server-Timing` and writes a fourth metric after the content. The lines of one section are joined into one list, in order; the two sections are not joined to each other. Whether the field may sit in a trailer section at all is RFC 9110 § 6.5.1's question and `message_trailer_fields_validity`'s to ask.

**`dur` is measured against HTML's *valid floating-point number*, and the finding is advice.** No sentence anywhere requires `dur` to be a number: § 3.2 parses it with HTML's rules for parsing floating-point number values and returns 0 if that is an error, which is a consequence and not a violation. The production is not `f64::from_str` either — that one accepts `inf`, `NaN` and a leading `+`, none of which HTML admits, and refuses `53abc`, which HTML's parser reads as 53. The rule's own doc comment used to state a SHOULD that appears in no document.

**A parameter name that is `dur` or `desc` in another case is reported as advice.** § 3.2 reads `params["dur"]` and § 3.3 reads `params["desc"]` — an ordered map keyed by the name as written — so `db;DUR=53` surfaces a duration of 0 and `db;DESC=x` an empty description. Nothing forbids the name; it is simply a parameter no user agent will recognise, which the document says is to be ignored without error.

**What is not reported.** An empty field value: `#server-timing-metric` has no floor, so `Server-Timing:` is zero metrics rather than an empty one — an empty *element* between commas is reported, on § 5.6.1.1's sender MUST NOT. Repeated `metric-name`s across metrics: § 2 grants a response a MAY to send them and requires the user agent to expose all of them. The order of metrics: the user agent MAY surface them in any order. An unregistered parameter name, which the document establishes exactly two of and tells recipients to ignore the rest of. And whether the numbers are true, which no capture can answer.

## Specifications

- [Server Timing §2](https://www.w3.org/TR/server-timing/#the-server-timing-header-field): The `Server-Timing` Header Field: the ABNF this rule enforces, the two parameter names the specification establishes, and the user-agent parsing algorithm. Eight BCP 14 keywords: six addressed to the user agent, a MAY permitting a response to repeat a metric name, and a SHOULD NOT on a parameter name appearing twice in one metric — that last one is the only sentence in the whole document that measures what a server wrote. The section takes `#`, `*`, `OWS`, `token` and `quoted-string` from `[RFC7230]`, which is obsolete; the current productions are RFC 9110 § 5.6.1, § 5.6.3, § 5.6.2 and § 5.6.4 and are carried forward unchanged, so nothing this rule decides turns on which document is read. The document is a W3C Working Draft (7 April 2026) whose own Status section says "It is inappropriate to cite this document as other than a work in progress" — and it is nonetheless the field's only specification: the IANA HTTP Field Name Registry lists `Server-Timing` as **permanent** with this document as its sole reference, the same way it lists `Keep-Alive` against an obsoleted RFC. A work in progress is what there is to read
- [Server Timing §3.2](https://www.w3.org/TR/server-timing/#dom-performanceservertiming-duration): The `duration` attribute: `params["dur"]` parsed with HTML's rules for parsing floating-point number values, returning 0 on error. This is what a non-numeric `dur` costs, and it is a consequence rather than a requirement — the lookup is by the exact string, which is why a differently-cased name surfaces nothing
- [Server Timing §3.3](https://www.w3.org/TR/server-timing/#dom-performanceservertiming-description): The `description` attribute: `params["desc"]` if it exists, otherwise the empty string. The same exact-string lookup as § 3.2's
- [IANA HTTP Field Name Registry](https://www.iana.org/assignments/http-fields/http-fields.xhtml): Where the claim above is checkable: `Server-Timing` is listed `permanent`, with the W3C Working Draft as its only reference. No branch of this rule consults the registry — the field's grammar comes from the document, not from an entry — but the footing does, and an operator asked to trust a work in progress should be able to see that IANA does
- [HTML Common Microsyntaxes §2.3.4.3](https://html.spec.whatwg.org/multipage/common-microsyntaxes.html#floating-point-numbers): Floating-point numbers: the *valid floating-point number* production a conforming author writes, kept deliberately apart from the *rules for parsing floating-point number values* a user agent runs. `dur` is measured against the first. Neither is `f64::from_str`, which admits Infinity, NaN and a leading `+`
- [RFC 9110 §2.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-2.2): Conformance and Error Handling: "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules." The Server Timing specification states no requirement on a server, so every grammar finding here rests on this sentence
- [RFC 9110 §5.6.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1): Lists (#rule ABNF Extension): `#element => [ 1#element ]` is why an empty `Server-Timing` field value is zero metrics and not a defect, and § 5.6.1.1's "a sender MUST NOT generate empty list elements" is why a comma with nothing between it and the next one is
- [RFC 9110 §5.6.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.2): Tokens: `metric-name` and both halves of a parameter's name are `token`, whose characters are all visible US-ASCII — so an `obs-text` octet in one of those positions is the defect, not the reader's inability to decode it
- [RFC 9110 §5.6.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.4): Quoted Strings: the other alternative a `server-timing-param-value` may be. `qdtext` admits `obs-text`, which is why a `desc` carrying a high octet is conforming, and `quoted-pair` is why a DQUOTE inside one is not a terminator
- [RFC 9110 §6.5.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-6.5.1): Limitations on Use of Trailers: the sentence that decides whether this field may sit in a trailer section at all. Not asked here — `message_trailer_fields_validity` owns it — but it is why the second section this rule reads is worth naming: the Server Timing specification puts the field there only in a section marked non-normative

## Configuration

```toml
[rules.server_timing_header_syntax]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good The specification's own worked exchange, including the trailer line

```http
Server-Timing: miss, db;dur=53, app;dur=47.2
Server-Timing: customView, dc;desc=atl
Server-Timing: cache;desc="Cache Read";dur=23.2
Trailer: Server-Timing
Server-Timing: total;dur=123.4
```

### ✅ Good A comma and a semicolon inside a quoted-string are data, not separators

```http
Server-Timing: cache;desc="Cache Read, DB Write", db;dur=.5e1
```

### ✅ Good An empty field value is zero metrics, which the list production allows

```http
Server-Timing:
```

### ❌ Bad Grammar: an empty list element, a metric-name that is not a token, a parameter with no value, and a value that is neither a token nor a quoted-string

```http
Server-Timing: ,miss
Server-Timing: b@d;dur=5
Server-Timing: db;desc
Server-Timing: db;desc=Cache Read
Server-Timing: db;desc="abc"x
```

### ❌ Bad Advice: a repeated parameter name, a `dur` that is not a valid floating-point number, and a name the getters will not find

```http
Server-Timing: db;dur=50;dur=51
Server-Timing: db;dur=NaN
Server-Timing: db;dur=+5
Server-Timing: db;DUR=53
```
