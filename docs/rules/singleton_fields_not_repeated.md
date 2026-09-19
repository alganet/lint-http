<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Singleton Fields Not Repeated

## Description

Reports a message writing more than one field line of a singleton field. RFC 9110 §5.3: a sender MUST NOT generate multiple field lines with the same name in a message — *whether in the headers or trailers* — unless at least one alternative of the field's definition allows a comma-separated list, and no definition of the twelve fields this rule counts has one. §5.5 is why the check is worth making at all: it asks senders to anticipate recombination *"since a singleton field might be erroneously sent with multiple members and detecting such errors improves interoperability"*.

**The count is per message, not per section.** §5.3's MUST NOT names the headers and trailers together — its second clause forbids *appending* a field line where one already exists — so a `Date` in the header section and another in the trailer section are two field lines of one message and are reported. (Most of these fields are also forbidden in trailers outright by other sentences; that is `trailer_fields_valid`'s question and does not change this one.)

**A field absent from the table draws nothing.** The exception clause turns on the field's *definition*, which a linter cannot read off the wire — so only fields whose grammars this catalogue has read and cited are counted, and an unknown field name is never assumed to be a singleton. The twelve are: `Server`, `User-Agent`, `Date`, `Last-Modified`, `Content-Range`, `Range`, `If-Range`, `Authorization`, `Proxy-Authorization`, `Age`, `Expires` and `Cookie` — for `Age`, RFC 9111 §5.1 says the word *singleton* outright, and for `Cookie` RFC 6265 §5.4 states the prohibition in as many words.

**`Cookie` is the one row a protocol version can excuse, and it is excused on two of them.** RFC 6265 §4.2.1 delimits `cookie-pair`s with a semicolon, so §5.2's comma cannot recombine the lines — RFC 9113 §8.2.3 says exactly that — and RFC 9113 §8.2.3 and RFC 9114 §4.2.1 then permit the split anyway, for compression, requiring the lines rejoined with `"; "` before the message is passed anywhere else. So a `Cookie` on several field lines is a defect over HTTP/1.1 and the recommended spelling over HTTP/2 and HTTP/3, and this rule reads the version **the field section itself arrived on** — a request received over one version and a response sent over another are judged separately. No other field in the table has such an exception, and both documents grant it by name.

**Thirteen singleton fields are deliberately not here**, because their repetition is already reported where their values are read, with the joined value in the finding: `Referer`, `Content-Location`, `Location`, `Max-Forwards`, `From`, `Content-Disposition`, `Content-Type`, `ETag` and `Retry-After` each carry the check in their own rule, `If-Modified-Since` and `If-Unmodified-Since` in `conditional_headers_consistent`, `Host` in `host_header` (where RFC 9112 §3.2 adds the recipient's 400), and `Content-Length` in the body-length rules — RFC 9110 §8.6 gives that field its own arithmetic for duplicate values, which is a different question from this rule's. The last five moved out of the table rather than being kept out of it: they were in both places, so one repetition drew this entry twice, and the rule reading the value is the one that can say what the repetition costs the recipient.

**What a recipient does with the repetition is each field's own hazard**, and this rule does not guess at it: the finding names the field's grammar and §5.3, not a reconstruction of what any particular recipient would read. §5.2's recombination is defined within a section, and for none of these fields does the recombined value derive from the field's grammar.

## Violations

- [field_line_duplicated](../violations/field_line_duplicated.md) — A field is written on more lines than its definition allows

## Specifications

- [RFC 9110 §5.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.3): Field Order — a sender MUST NOT write multiple field lines of one name, in the headers or the trailers, unless at least one alternative of the field's definition allows the lines to be recombined as a comma-separated list
- [RFC 9110 §5.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.5): Field Values: what a singleton field is, and the sentence saying that detecting an erroneously repeated one improves interoperability
- [RFC 9110 §5.6.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1): Lists: the `#rule` extension — the shape a field's definition has when §5.3's exception applies to it, and the shape none of the eleven grammars in this rule's table has
- [RFC 9111 §5.1](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.1): Age — defined as a singleton header field in as many words, with the recipient's first-member recovery beside it, which is a recipient's SHOULD and not a sender's licence
- [RFC 6265 §5.4](https://www.rfc-editor.org/rfc/rfc6265.html#section-5.4): The Cookie Header — a user agent MUST NOT attach more than one Cookie header field to a request it generates
- [RFC 9113 §8.2.3](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.2.3): Compressing the Cookie Header Field — the semicolon that keeps §5.2 from recombining the field, and the compression exception that permits the split anyway, rejoined with "; "
- [RFC 9114 §4.2.1](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.2.1): Field Compression — HTTP/3's statement of the same exception, before compression rather than after it

## Configuration

```toml
[rules.singleton_fields_not_repeated]
# RFC 9110 §5.3's MUST NOT is unconditional, so the shipped severity is error:
# a second field line of a singleton is a defect of the message however a
# recipient recovers from it.
enabled = true
```

## Examples

### ✅ Good

```http
HTTP/1.1 200 OK
Date: Tue, 15 Nov 1994 08:12:31 GMT
Content-Type: text/plain

Hello
```

### ✅ Good (a list field may span field lines — not this rule's subject)

```http
HTTP/1.1 200 OK
Cache-Control: max-age=60
Cache-Control: must-revalidate
```

### ❌ Bad (two Date field lines — `Date = HTTP-date` has no list alternative)

```http
HTTP/1.1 200 OK
Date: Tue, 15 Nov 1994 08:12:31 GMT
Date: Wed, 16 Nov 1994 08:12:31 GMT
```

### ❌ Bad (two Age field lines — RFC 9111 §5.1 calls the field a singleton)

```http
HTTP/1.1 200 OK
Age: 60
Age: 120
```

### ❌ Bad (two Cookie field lines over HTTP/1.1 — the pairs belong on one line, joined with `; `)

```http
GET / HTTP/1.1
Host: example.com
Cookie: a=1
Cookie: b=2
```

### ✅ Good (the same two lines over HTTP/2 — RFC 9113 §8.2.3 splits Cookie for compression, and RFC 9114 §4.2.1 says the same of HTTP/3)

```http
GET / HTTP/2.0
Host: example.com
Cookie: a=1
Cookie: b=2
```
