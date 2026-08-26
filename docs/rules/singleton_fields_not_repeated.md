<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Singleton Fields Not Repeated

## Description

Reports a message writing more than one field line of a singleton field. RFC 9110 §5.3: a sender MUST NOT generate multiple field lines with the same name in a message — *whether in the headers or trailers* — unless at least one alternative of the field's definition allows a comma-separated list, and no definition of the sixteen fields this rule counts has one. §5.5 is why the check is worth making at all: it asks senders to anticipate recombination *"since a singleton field might be erroneously sent with multiple members and detecting such errors improves interoperability"*.

**The count is per message, not per section.** §5.3's MUST NOT names the headers and trailers together — its second clause forbids *appending* a field line where one already exists — so a `Date` in the header section and another in the trailer section are two field lines of one message and are reported. (Most of these fields are also forbidden in trailers outright by other sentences; that is `trailer_fields_valid`'s question and does not change this one.)

**A field absent from the table draws nothing.** The exception clause turns on the field's *definition*, which a linter cannot read off the wire — so only fields whose grammars this catalogue has read and cited are counted, and an unknown field name is never assumed to be a singleton. The sixteen are: `Server`, `User-Agent`, `Date`, `Last-Modified`, `ETag`, `Content-Type`, `Content-Range`, `Range`, `If-Range`, `If-Modified-Since`, `If-Unmodified-Since`, `Authorization`, `Proxy-Authorization`, `Retry-After`, `Age` and `Expires` — for `Age`, RFC 9111 §5.1 says the word *singleton* outright.

**Eight singleton fields are deliberately not here**, because their repetition is already reported where their values are read, with the joined value in the finding: `Referer`, `Content-Location`, `Location`, `Max-Forwards`, `From` and `Content-Disposition` each carry the check in their own rule, `Host` in `host_header` (where RFC 9112 §3.2 adds the recipient's 400), and `Content-Length` in the body-length rules — RFC 9110 §8.6 gives that field its own arithmetic for duplicate values, which is a different question from this rule's.

**What a recipient does with the repetition is each field's own hazard**, and this rule does not guess at it: the finding names the field's grammar and §5.3, not a reconstruction of what any particular recipient would read. §5.2's recombination is defined within a section, and for none of these fields does the recombined value derive from the field's grammar.

## Specifications

- [RFC 9110 §5.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.3): Field Order: the MUST NOT this rule enforces — multiple field lines with one name in a message, headers or trailers, unless the field's definition has a comma-separated-list alternative
- [RFC 9110 §5.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.5): Field Values: what a singleton field is, and the sentence saying that detecting an erroneously repeated one improves interoperability
- [RFC 9110 §5.6.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1): Lists: the `#rule` extension — the shape a field's definition has when §5.3's exception applies to it, and the shape none of the sixteen grammars in this rule's table has
- [RFC 9111 §5.1](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.1): Age — defined as a singleton header field in as many words, with the recipient's first-member recovery beside it, which is a recipient's SHOULD and not a sender's licence

## Configuration

```toml
[rules.singleton_fields_not_repeated]
# RFC 9110 §5.3's MUST NOT is unconditional, so the shipped severity is error:
# a second field line of a singleton is a defect of the message however a
# recipient recovers from it.
enabled = true
severity = "error"
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

### ❌ Bad (two Content-Type field lines)

```http
HTTP/1.1 200 OK
Content-Type: text/html
Content-Type: text/plain
```
