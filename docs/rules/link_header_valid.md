<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Link Header Valid

## Description

Parses the `Link` field of a request and of a response — every field line of one section joined into the single list they are — against the grammar RFC 8288 §3 writes for it: `Link = #link-value`, `link-value = "<" URI-Reference ">" *( OWS ";" OWS link-param )` and `link-param = token BWS [ "=" BWS ( token / quoted-string ) ]`. On top of the grammar it reports the three requirements the document states about a member: that `rel` is present, that `rel` and the four attributes §3.4.1 bounds appear at most once, and that each relation type derives from one of the two productions §3.3 offers. Two of §3.4.1's per-attribute value grammars are measured after unquoting, through the imports §1.1 makes by name: `hreflang` against RFC 5646's `Language-Tag` and `type` against RFC 6838 §4.2's `type-name "/" subtype-name`.

**A `type` value is measured against `restricted-name`, not `token`, and it has no parameters.** §3.4.1's ABNF for the value ends at the subtype-name, so `type="text/html;charset=utf-8"` derives from nothing — the `;` is an octet `restricted-name-chars` does not admit, not the start of a parameters group — and `restricted-name` opens on a letter or digit, so `type="*/*"` is a finding here where `Accept`'s own grammar makes the same characters a media range. The hint itself binds nothing: the document says in as many words that it does not override `Content-Type`, and this rule reads the value's grammar, never the response it points at.

**The `hreflang` check is the catalogue's conservative Language-Tag floor.** The shared validator enforces what RFC 5646 §2.1's prose states — alphanumeric subtags, hyphen-separated, at most eight characters, a first subtag of letters — and deliberately not the full ABNF, because quoting more would claim a check not performed. Every occurrence is judged: repeating the attribute is conforming (it is §3.4.1's way of saying several languages are available), and each repetition still owes the production.

**A relation type may be a URI, and that is the document's own example.** `relation-type = reg-rel-type / ext-rel-type`, where `ext-rel-type = URI` — so `Link: </>; rel="http://example.net/foo"`, printed in §3.5, derives from the grammar. Measuring a relation type against `tchar` reports every extension relation type there is, because a URI holds `:` and `/` and a `token` holds neither. `reg-rel-type` is narrower than `token` in the other direction — `LOALPHA *( LOALPHA / DIGIT / "." / "-" )` admits no capital and no `_` — so the two productions are checked as the alternation they are, and a value matching neither is named against both.

**A link-param may have no value.** The `=` and the word after it are inside the optional group, so `Link: <https://example.com/>; rel=next; nofollow` is a conforming member. What the document does require is a *word* once the `=` is written, which is why `rel=` is still reported.

**Commas inside a member are data.** A `URI-Reference` admits `,` as a `sub-delim` and a `quoted-string` admits it as `qdtext`; §3.3 says so in as many words when it requires an extension relation type to be quoted if it holds one. The members are therefore cut at the commas outside both `<>` and `""`, and `Link: </a,b>; rel=next` is one link and not two malformed ones.

**What §3.4.1's `as` findings rest on, and where.** No RFC requires an `as` parameter of anything: `preload` and `as` are HTML's, and the sentences that make their pairing observable are in the HTML Standard's *Processing `Link` headers* algorithm, which runs over a **response**'s header list and returns early when `attribs["as"]` does not exist — or when its value translates to null. So the member is not malformed — it is discarded by the recipient it was written for, and both findings say that rather than inventing a requirement. On a request neither is reported at all, because that algorithm never sees one.

**An `as` value is measured against HTML's six preload destinations, not Fetch's table.** *Translate a preload destination* refuses membership before Fetch's *translate a potential destination* is ever consulted, so the set is `fetch`, `font`, `image`, `script`, `style`, `track` — and `as=document`, a Fetch destination, is discarded like any other non-member, while `as=fetch` conforms. The match keeps case, and deliberately: the neighbouring steps of the same algorithm say *"an ASCII case-insensitive match"* about `crossorigin` and `fetchpriority` in as many words and this step says nothing of the kind, so `as=Font` is a string the set does not hold. A repeated `as` is not reported and only the first is judged: RFC 8288's parsing algorithm deduplicates only the four attributes §3.4.1 bounds, and the map read HTML performs takes the first entry.

**RFC 8297 requires nothing of a `Link` in a 103.** Its five modals are two MUST NOTs and a SHOULD NOT addressed to the client about what it does with fields it received, plus two MAYs handed to the server; none of them is about this field's content. The status-gated check this replaces asked a 103's members for a `rel` and let every other response omit it — a narrower rendering of §3.3's MUST, which is stated once for every link-value there is.

**What this rule does not decide.**

- **What a `media` value holds.** §1.1 imports its production — `media-query-list` — from the dated 2012 CSS3 Media Queries Recommendation: a grammar in CSS's formalism rather than ABNF, from a document this catalogue does not read, whose own error handling folds a query it cannot parse to `not all` rather than refusing it. Measuring a value against the pinned 2012 grammar would adjudicate a drift this catalogue has not audited — the Media Queries syntax senders write today derives range forms the 2012 document does not print — and a floor loose enough to sidestep the drift would measure nothing. §3.4.1's one MUST about the value (quote it if it holds a `;` or `,`) needs no rule, because the serialisation enforces it itself: unquoted, those characters are this field's own delimiters, so the value never arrives as one value to ask about.
- **Where a relative `URI-Reference` resolves.** §3.1 and §3.2 make that a parser's MUST and it needs a base the field does not carry.
- **`rev`.** §3.3 deprecates it in a sentence holding no BCP 14 keyword at all, so nothing there makes writing it a defect.
- **Whether the target exists, or the relation type is registered.** §2.1.1.2 registers relation types under Specification Required and §2.1.2 hands every unregistered name to the URI form, so an unrecognised lowercase name is an extension the registry has not been asked about — not a finding.

## Specifications

- [RFC 8288 §3](https://www.rfc-editor.org/rfc/rfc8288.html#section-3): The serialisation: `Link = #link-value`, the angle-bracketed `URI-Reference`, and `link-param = token BWS [ "=" BWS ( token / quoted-string ) ]` — whose optional group is what makes a valueless parameter conforming. Also the sentence equating the token and quoted-string forms, which is why a value is judged after unquoting
- [RFC 8288 §3.1](https://www.rfc-editor.org/rfc/rfc8288.html#section-3.1): The link target: one IRI converted to a `URI-Reference` and written inside angle brackets. The conversion is why an octet no URI admits is a finding rather than an encoding question
- [RFC 8288 §3.3](https://www.rfc-editor.org/rfc/rfc8288.html#section-3.3): `rel` MUST be present and MUST NOT appear more than once; its value is `relation-type *( 1*SP relation-type )`; `relation-type = reg-rel-type / ext-rel-type` with `ext-rel-type = URI`, required to be absolute. The section that makes a URI-shaped relation type conforming and a capital letter in a registered one not
- [RFC 8288 §3.4.1](https://www.rfc-editor.org/rfc/rfc8288.html#section-3.4.1): The four serialisation-defined attributes this document bounds to one occurrence — `media`, `title`, `title*`, `type` — each in its own MUST NOT. `hreflang` is the one it deliberately leaves unbounded, saying that repeating it means several languages are available. Also the per-attribute value ABNFs: `Language-Tag` for `hreflang`, `type-name "/" subtype-name` for `type`, and `media-query-list` for `media` — the first two measured here, the third declined for the reasons the description gives
- [RFC 8288 §2.1.1](https://www.rfc-editor.org/rfc/rfc8288.html#section-2.1.1): Registered relation type names conform to `reg-rel-type` and are compared case-insensitively — the sentence behind folding case when asking whether a relation type is `preload`
- [RFC 8288 §2.1.2](https://www.rfc-editor.org/rfc/rfc8288.html#section-2.1.2): Extension relation types are URIs that uniquely identify the relation, compared as strings. Why a value matching no registered spelling is measured as a URI rather than reported
- [RFC 8288 §2.2](https://www.rfc-editor.org/rfc/rfc8288.html#section-2.2): Target attribute names are compared case-insensitively — the MUST behind recognising `rel`, `as` and the bounded four whatever case they were written in. Its `SHOULD NOT include "%", "'", or "*"` is advice about portability across serialisations and is not enforced here: §3.4.1 of this same document defines `title*`
- [RFC 8288 §1.1](https://www.rfc-editor.org/rfc/rfc8288.html#section-1.1): Which document's notation governs: the `#rule`, `token`, `quoted-string`, `BWS`, `OWS` and `LOALPHA` are imported rather than redefined, so the shared helpers that transcribe them are the right readers here. Its second list imports the value productions by name — `URI` and `URI-Reference` from RFC 3986, `type-name` and `subtype-name` from RFC 6838, `Language-Tag` from RFC 5646, and `media-query-list` from the 2012 CSS3 Media Queries Recommendation, which is why a `media` value is the one this rule does not measure
- [RFC 8288 §1.2](https://www.rfc-editor.org/rfc/rfc8288.html#section-1.2): The bridge to a modal: this document states no requirement of its own that a value match its ABNF, it adopts the core specification's conformance section — which is RFC 9110 §2.2 in the document now in force
- [RFC 9110 §2.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-2.2): The sender MUST NOT behind every grammar finding here: a member deriving from none of §3's productions is a protocol element matching no ABNF rule
- [RFC 9110 §5.6.1.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1.1): The list construct: `#` sets no minimum, so an empty `Link:` declares no link rather than declaring one badly — and a sender MUST NOT write an empty element between two real ones
- [RFC 9110 §5.6.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.3): `BWS` is admitted beside the `=` for historical reasons and a sender MUST NOT generate it — the half of the production that makes the recipient's trim required and the sender's whitespace a finding
- [RFC 9110 §5.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.2): Repeated `Link` field lines are one list. RFC 8288 §3.5 shows the same thing from the other side, printing a two-member field value and the two field lines it is equivalent to
- [RFC 3986 §3](https://www.rfc-editor.org/rfc/rfc3986.html#section-3): `URI` — the production `ext-rel-type` is, and the reason a relation type with a scheme is read as one instead of being measured against `tchar`. `URI-Reference` (§4.1) is the target's
- [RFC 5646 §2.1](https://www.rfc-editor.org/rfc/rfc5646.html#section-2.1): Syntax: `Language-Tag`, the whole of §3.4.1's ABNF for an `hreflang` value. What is enforced is the catalogue's shared conservative floor — subtag shape, from this section's prose — not the full grammar and not the registry
- [RFC 6838 §4.2](https://www.rfc-editor.org/rfc/rfc6838.html#section-4.2): Naming Requirements: `restricted-name`, the production behind both halves of a `type` value. It opens on a letter or digit and closes at 127 characters, and §3.4.1's ABNF for the value ends at the subtype-name, so there is no parameters group and no wildcard here
- [HTML Semantics §4.2.4.4](https://html.spec.whatwg.org/multipage/semantics.html#processing-link-headers): *Processing `Link` headers* — the algorithm that reads this field out of a **response** and, for `rel=preload`, returns early when `as` does not exist. The only published sentence pairing the two, and the reason that finding is worded as a member being discarded rather than as a MUST
- [HTML Links §4.6.8.20](https://html.spec.whatwg.org/multipage/links.html#link-type-preload): Where the `preload` keyword itself is defined, and where it says the resource is fetched *according to the preload destination given by the `as` attribute*. The old reference here named a retired W3C Preload specification in its note while pointing at this page
- [HTML Links §4.6.8.20](https://html.spec.whatwg.org/multipage/links.html#preload-destination): *Preload destination* — the six strings the header path admits — and *translate a preload destination*, which returns null for anything else before Fetch's own translation is consulted. The reason the table here holds six values and not Fetch's twenty
- [RFC 8297 §2](https://www.rfc-editor.org/rfc/rfc8297.html#section-2): Early Hints. Named because a check here used to be gated on the 103 status and rest on this document: it states nothing about a `Link` member's content, and its modals are addressed to the client

## Configuration

```toml
[rules.link_header_valid]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good Response

```http
HTTP/1.1 200 OK
Link: <https://example.com/style.css>; rel=preload; as=style
Link: <https://example.com/page2>; rel="next"; title="Next page"
```

### ✅ Good (an extension relation type is a URI — RFC 8288 §3.5's own example)

```http
HTTP/1.1 200 OK
Link: </>; rel="http://example.net/foo"
```

### ✅ Good (the optional group makes a valueless parameter conforming)

```http
HTTP/1.1 200 OK
Link: <https://example.com/>; rel=next; nofollow
```

### ✅ Good (a comma inside the target is a sub-delim, not a separator)

```http
HTTP/1.1 200 OK
Link: </a,b>; rel=next, </c>; rel=prev
```

### ✅ Good Request

```http
POST /uploads HTTP/1.1
Host: example.com
Link: <https://example.com/types/photo>; rel="type"
```

### ❌ Bad (no angle brackets around the target)

```http
HTTP/1.1 200 OK
Link: https://example.com/style.css; rel=preload; as=style
```

### ❌ Bad (§3.3 requires rel in every link-value)

```http
HTTP/1.1 200 OK
Link: <https://example.com/>; title="Home"
```

### ❌ Bad (neither a reg-rel-type nor an absolute URI)

```http
HTTP/1.1 200 OK
Link: <https://example.com/>; rel=Next
```

### ❌ Bad (rel twice in one link-value)

```http
HTTP/1.1 200 OK
Link: <https://example.com/>; rel=next; rel=prev
```

### ❌ Bad (BWS beside the "=")

```http
HTTP/1.1 200 OK
Link: <https://example.com/>; rel = next
```

### ❌ Bad (the HTML processing model drops a preload with no as)

```http
HTTP/1.1 103 Early Hints
Link: <https://example.com/script.js>; rel=preload
```

### ❌ Bad (as=document is a Fetch destination, but not one of HTML's six preload destinations)

```http
HTTP/1.1 200 OK
Link: <https://example.com/next>; rel=preload; as=document
```

### ❌ Bad (an invalid character in a parameter name)

```http
HTTP/1.1 200 OK
Link: <https://example.com/>; rel=next; bad@=1
```

### ✅ Good (hreflang and type values, measured after unquoting)

```http
HTTP/1.1 200 OK
Link: <https://example.com/de>; rel=alternate; hreflang=de; type="text/html"
```

### ❌ Bad (an hreflang value that is not a Language-Tag)

```http
HTTP/1.1 200 OK
Link: <https://example.com/>; rel=alternate; hreflang=en_US
```

### ❌ Bad (a type value with no subtype-name after a '/')

```http
HTTP/1.1 200 OK
Link: <https://example.com/>; rel=alternate; type=text
```
