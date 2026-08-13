<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Link Header Validity

## Description

Parses the `Link` field of a request and of a response — every field line of one section joined into the single list they are — against the grammar RFC 8288 §3 writes for it: `Link = #link-value`, `link-value = "<" URI-Reference ">" *( OWS ";" OWS link-param )` and `link-param = token BWS [ "=" BWS ( token / quoted-string ) ]`. On top of the grammar it reports the three requirements the document states about a member: that `rel` is present, that `rel` and the four attributes §3.4.1 bounds appear at most once, and that each relation type derives from one of the two productions §3.3 offers.

**A relation type may be a URI, and that is the document's own example.** `relation-type = reg-rel-type / ext-rel-type`, where `ext-rel-type = URI` — so `Link: </>; rel="http://example.net/foo"`, printed in §3.5, derives from the grammar. Measuring a relation type against `tchar` reports every extension relation type there is, because a URI holds `:` and `/` and a `token` holds neither. `reg-rel-type` is narrower than `token` in the other direction — `LOALPHA *( LOALPHA / DIGIT / "." / "-" )` admits no capital and no `_` — so the two productions are checked as the alternation they are, and a value matching neither is named against both.

**A link-param may have no value.** The `=` and the word after it are inside the optional group, so `Link: <https://example.com/>; rel=next; nofollow` is a conforming member. What the document does require is a *word* once the `=` is written, which is why `rel=` is still reported.

**Commas inside a member are data.** A `URI-Reference` admits `,` as a `sub-delim` and a `quoted-string` admits it as `qdtext`; §3.3 says so in as many words when it requires an extension relation type to be quoted if it holds one. The members are therefore cut at the commas outside both `<>` and `""`, and `Link: </a,b>; rel=next` is one link and not two malformed ones.

**What §3.4.1's `as` finding rests on, and where.** No RFC requires an `as` parameter of anything: `preload` and `as` are HTML's, and the sentence that makes their pairing observable is in the HTML Standard's *Processing `Link` headers* algorithm, which runs over a **response**'s header list and returns early when `attribs["as"]` does not exist. So the member is not malformed — it is discarded by the recipient it was written for, and the finding says that rather than inventing a requirement. On a request it is not reported at all, because that algorithm never sees one.

**RFC 8297 requires nothing of a `Link` in a 103.** Its five modals are two MUST NOTs and a SHOULD NOT addressed to the client about what it does with fields it received, plus two MAYs handed to the server; none of them is about this field's content. The status-gated check this replaces asked a 103's members for a `rel` and let every other response omit it — a narrower rendering of §3.3's MUST, which is stated once for every link-value there is.

**What this rule does not decide.**

- **What the serialisation-defined attributes hold.** §3.4.1 gives `hreflang` a `Language-Tag`, `media` a `media-query-list`, and `type` a `type-name "/" subtype-name`. Each is a production from a different document — the middle one from a CSS specification this catalogue does not read — and each is its own audit. The `link-param` grammar around them is enforced; their values are not.
- **Whether an `as` value names a preload destination.** The same HTML algorithm drops the member when `as` translates to nothing, but the set of destinations lives in Fetch and would have to be transcribed and kept in step here. Being wrong about it costs a false report on an otherwise conforming member, so the question is carried rather than guessed at.
- **Where a relative `URI-Reference` resolves.** §3.1 and §3.2 make that a parser's MUST and it needs a base the field does not carry.
- **`rev`.** §3.3 deprecates it in a sentence holding no BCP 14 keyword at all, so nothing there makes writing it a defect.
- **Whether the target exists, or the relation type is registered.** §2.1.1.2 registers relation types under Specification Required and §2.1.2 hands every unregistered name to the URI form, so an unrecognised lowercase name is an extension the registry has not been asked about — not a finding.

## Specifications

- [RFC 8288 §3](https://www.rfc-editor.org/rfc/rfc8288.html#section-3): The serialisation: `Link = #link-value`, the angle-bracketed `URI-Reference`, and `link-param = token BWS [ "=" BWS ( token / quoted-string ) ]` — whose optional group is what makes a valueless parameter conforming. Also the sentence equating the token and quoted-string forms, which is why a value is judged after unquoting
- [RFC 8288 §3.1](https://www.rfc-editor.org/rfc/rfc8288.html#section-3.1): The link target: one IRI converted to a `URI-Reference` and written inside angle brackets. The conversion is why an octet no URI admits is a finding rather than an encoding question
- [RFC 8288 §3.3](https://www.rfc-editor.org/rfc/rfc8288.html#section-3.3): `rel` MUST be present and MUST NOT appear more than once; its value is `relation-type *( 1*SP relation-type )`; `relation-type = reg-rel-type / ext-rel-type` with `ext-rel-type = URI`, required to be absolute. The section that makes a URI-shaped relation type conforming and a capital letter in a registered one not
- [RFC 8288 §3.4.1](https://www.rfc-editor.org/rfc/rfc8288.html#section-3.4.1): The four serialisation-defined attributes this document bounds to one occurrence — `media`, `title`, `title*`, `type` — each in its own MUST NOT. `hreflang` is the one it deliberately leaves unbounded, saying that repeating it means several languages are available
- [RFC 8288 §2.1.1](https://www.rfc-editor.org/rfc/rfc8288.html#section-2.1.1): Registered relation type names conform to `reg-rel-type` and are compared case-insensitively — the sentence behind folding case when asking whether a relation type is `preload`
- [RFC 8288 §2.1.2](https://www.rfc-editor.org/rfc/rfc8288.html#section-2.1.2): Extension relation types are URIs that uniquely identify the relation, compared as strings. Why a value matching no registered spelling is measured as a URI rather than reported
- [RFC 8288 §2.2](https://www.rfc-editor.org/rfc/rfc8288.html#section-2.2): Target attribute names are compared case-insensitively — the MUST behind recognising `rel`, `as` and the bounded four whatever case they were written in. Its `SHOULD NOT include "%", "'", or "*"` is advice about portability across serialisations and is not enforced here: §3.4.1 of this same document defines `title*`
- [RFC 8288 §1.1](https://www.rfc-editor.org/rfc/rfc8288.html#section-1.1): Which document's notation governs: the `#rule`, `token`, `quoted-string`, `BWS`, `OWS` and `LOALPHA` are imported rather than redefined, so the shared helpers that transcribe them are the right readers here
- [RFC 8288 §1.2](https://www.rfc-editor.org/rfc/rfc8288.html#section-1.2): The bridge to a modal: this document states no requirement of its own that a value match its ABNF, it adopts the core specification's conformance section — which is RFC 9110 §2.2 in the document now in force
- [RFC 9110 §2.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-2.2): The sender MUST NOT behind every grammar finding here: a member deriving from none of §3's productions is a protocol element matching no ABNF rule
- [RFC 9110 §5.6.1.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1.1): The list construct: `#` sets no minimum, so an empty `Link:` declares no link rather than declaring one badly — and a sender MUST NOT write an empty element between two real ones
- [RFC 9110 §5.6.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.3): `BWS` is admitted beside the `=` for historical reasons and a sender MUST NOT generate it — the half of the production that makes the recipient's trim required and the sender's whitespace a finding
- [RFC 9110 §5.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.2): Repeated `Link` field lines are one list. RFC 8288 §3.5 shows the same thing from the other side, printing a two-member field value and the two field lines it is equivalent to
- [RFC 3986 §3](https://www.rfc-editor.org/rfc/rfc3986.html#section-3): `URI` — the production `ext-rel-type` is, and the reason a relation type with a scheme is read as one instead of being measured against `tchar`. `URI-Reference` (§4.1) is the target's
- [HTML Semantics §4.2.4.4](https://html.spec.whatwg.org/multipage/semantics.html#processing-link-headers): *Processing `Link` headers* — the algorithm that reads this field out of a **response** and, for `rel=preload`, returns early when `as` does not exist. The only published sentence pairing the two, and the reason that finding is worded as a member being discarded rather than as a MUST
- [HTML Links §4.6.8.20](https://html.spec.whatwg.org/multipage/links.html#link-type-preload): Where the `preload` keyword itself is defined, and where it says the resource is fetched *according to the preload destination given by the `as` attribute*. The old reference here named a retired W3C Preload specification in its note while pointing at this page
- [RFC 8297 §2](https://www.rfc-editor.org/rfc/rfc8297.html#section-2): Early Hints. Named because a check here used to be gated on the 103 status and rest on this document: it states nothing about a `Link` member's content, and its modals are addressed to the client

## Configuration

```toml
[rules.message_link_header_validity]
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

### ❌ Bad (an invalid character in a parameter name)

```http
HTTP/1.1 200 OK
Link: <https://example.com/>; rel=next; bad@=1
```
