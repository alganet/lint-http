<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Content Encoding And Type Consistent

## Description

Validate `Content-Encoding` header members for common correctness issues: members must be valid `token`s, a wildcard `*` is rejected (it belongs to `Accept-Encoding`), and a coding repeated within the field is flagged.

Responses that carry no content (1xx, 204, 304) are flagged for sending `Content-Encoding` at all, and **the two cases are reported separately** because their evidence differs in kind. A 304 answers to RFC 9110 §15.4.5, which tells a sender not to generate representation metadata beyond a listed set. A 1xx or 204 answers to nothing: no sentence says it, and §15.3.5 leans the other way — a 204's metadata "refer to the target resource and its selected representation after the requested action was applied", which makes describing a representation the client is not receiving a defensible thing to do. The inference is kept because in traffic it is far more often a proxy adding a coding header to a response it never encoded, and it is a separate violation id so that an operator who disagrees can silence it without losing the finding the document does state.

Repeating a coding is likewise a judgement call rather than a conformance failure — `gzip, gzip` legitimately expresses gzip applied twice — but in practice it usually means two layers each added the header.

**Note:** despite the rule's name, no `Content-Type` consistency check is performed; the rule inspects `Content-Encoding` only.

**The value is read as octets and over the whole field section.** Every character of a `token` is visible US-ASCII, so an `obs-text` octet in a coding name is reported for what it is — a character the production does not admit, named as the byte it is — rather than as a verdict about the field's encoding. It used to be the second: a value the string reader refused was reported as *not valid UTF-8*, which is a claim about the whole value where the defect is one character of one member. The lines of a section are joined first, because `#content-coding` makes them one list.

## Specifications

- [RFC 9110 §8.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.4): `Content-Encoding = #content-coding`, and the reservation of `identity` for Accept-Encoding — the reason it is flagged here
- [RFC 9110 §12.5.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-12.5.3): The wider Accept-Encoding grammar (`codings = content-coding / "identity" / "*"`), which is why the two headers are checked against different vocabularies
- [RFC 9110 §15.4.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4.5): 304 Not Modified — the fields a 304 MUST send, the SHOULD NOT against any other representation metadata unless it guides cache updates, and the response being terminated by the end of the header section
- [RFC 9110 §15.3.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.3.5): 204 No Content — the response is terminated by the end of its header section and cannot contain content, and its metadata refers to the target resource and its selected representation after the action was applied
- [RFC 9110 §5.6.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.2): Tokens — `token = 1*tchar`, and the fifteen punctuation marks besides the digits and letters that `tchar` admits

## Configuration

```toml
[rules.content_encoding_and_type_consistent]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
HTTP/1.1 200 OK
Content-Encoding: gzip, br
Content-Type: application/json; charset=utf-8

...compressed JSON body...
```

### ❌ Bad (duplicate coding)

```http
HTTP/1.1 200 OK
Content-Encoding: gzip, gzip
Content-Type: application/json

...compressed JSON body...
```

### ❌ Bad (Content-Encoding on no-body response)

```http
HTTP/1.1 204 No Content
Content-Encoding: gzip
```
