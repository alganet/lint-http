<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Server No Body For 1xx, 204, 304

## Description

A `1xx (Informational)`, `204 (No Content)` or `304 (Not Modified)` response *"is terminated by the end of the header section; it cannot contain content or trailers"* — RFC 9110 writes that sentence once per status (§15.2, §15.3.5, §15.4.5), and RFC 9112 §6.3 restates it as framing: such a response ends at the first empty line *"regardless of the header fields present in the message"*.

**Four findings, and they are not the same kind.** Two read what actually arrived, and are the violation itself: content octets in the response body, and a trailer section. Two read a header field, and are a violation of that field's own prohibition rather than evidence of a body — because no field can make one of these responses carry one.

- **Content.** Any captured content octet is reported, for all three statuses. The count is of content in §6.4's sense, so chunk sizes and the trailer section are not in it. Of the two other rules that read the captured length for these statuses, one reaches its check only when a valid `Content-Length` is present and has handed these statuses over, and the other checked `1xx` alone and only when both request and response were HTTP/3; so a `204` answering with a chunked body and no declared length is seen here and was seen nowhere before.
- **Trailers.** A trailer section is reported for all three statuses, whether or not it carries any fields: what the sentences forbid is the section. Which fields a trailer section may hold, when one is allowed, is `message_trailer_fields_validity`.
- **`Content-Length`.** Reported on `1xx` and `204` only, at **any value including `0`** — §8.6's prohibition is on the field, not on a number. No value is parsed; `content_length_valid` owns the field's syntax.
- **`Transfer-Encoding`.** Reported on `1xx` and `204` only, by RFC 9112 §6.1's matching MUST NOT.

**The `304` is exempt from both field checks, by name, in both documents.** §8.6 says a server *"MAY send a Content-Length header field in a 304 (Not Modified) response to a conditional GET request"*, and RFC 9112 §6.1 says *"Transfer-Encoding MAY be sent in a response to a HEAD request or in a 304 (Not Modified) response … to a GET request"*. In a 304 both fields describe the `200` that was not sent. Each MAY carries a MUST NOT of its own — the value must equal what the unsent `200` would have had — and **that requirement is not enforced here and cannot be**: the octets it compares against were never transferred, so no single exchange holds them.

**Versions.** §8.6 is RFC 9110's and applies to every version, so the `Content-Length` check is not gated. RFC 9112 §6.1 is HTTP/1.1's, and HTTP/2 and HTTP/3 do not have `Transfer-Encoding` at all — there the field's *presence* is the defect and the status is beside the point, so this rule declines: `no_connection_specific_fields` reports it on both, against whichever version carried the field section it is in.

**`205 (Reset Content)` is not in this set.** Its prohibition (§15.3.6, *"a server MUST NOT generate content in a 205 response"*) is about generating content, and its framing is ordinary — so `Content-Length: 0` on a `205` is conforming where the same field on a `204` violates a MUST NOT. It needs its own rule, not a fourth status here.

## Specifications

- [RFC 9110 §15.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.2): Informational 1xx — "A 1xx response is terminated by the end of the header section; it cannot contain content or trailers"
- [RFC 9110 §15.3.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.3.5): 204 (No Content) — the same sentence, written again for this status
- [RFC 9110 §15.4.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4.5): 304 (Not Modified) — the same sentence a third time. It forbids content and trailers, and says nothing against the two header fields that describe the 200 that was not sent
- [RFC 9110 §8.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.6): Content-Length — a MUST NOT on 1xx and 204 at any value, and a MAY on a 304 to a conditional GET. That MAY's own MUST NOT (the value must equal the unsent 200's content length) is undecidable from one exchange and is left unenforced
- [RFC 9110 §6.4.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-6.4.1): Content Semantics — the summary this rule is named after. It is about content, not about header fields; taking it for a rule about fields is what put the 304 in front of two prohibitions that exempt it
- [RFC 9110 §15.3.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.3.6): 205 (Reset Content) — bodiless by a MUST NOT of its own, but with ordinary framing, so it is not reported by this rule and has none of its own
- [RFC 9112 §6.3](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.3): Message body length, item 1 — these responses end at the first empty line "regardless of the header fields present", which is why a field's presence is its own defect rather than evidence of a body
- [RFC 9112 §6.1](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.1): Transfer-Encoding — a MUST NOT on 1xx and 204, and a MAY on a 304 to a GET. HTTP/1.1's document, so the check does not run on later versions
- [RFC 9113 §8.2.2](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.2.2): HTTP/2 — Transfer-Encoding is connection-specific and must not appear at all, whatever the status. No rule reports it yet
- [RFC 9114 §4.1](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.1): HTTP/3 — transfer codings are not defined and the field must not be used; no_connection_specific_fields reports it. The same section repeats the trailers half for interim responses

## Configuration

```toml
[rules.no_body_for_1xx_204_304]
enabled = true
severity = "error"
```

## Examples

### ✅ Good 204 — metadata about the resource, and nothing else

```http
HTTP/1.1 204 No Content
ETag: "abc"
Date: Mon, 01 Jan 2024 00:00:00 GMT
```

### ✅ Good 304 — Content-Length describes the 200 that was not sent

```http
HTTP/1.1 304 Not Modified
ETag: "abc"
Content-Length: 1024
```

### ❌ Bad 204 — the field is forbidden at any value, including 0

```http
HTTP/1.1 204 No Content
Content-Length: 0
```

### ❌ Bad 100 — Transfer-Encoding on an interim response

```http
HTTP/1.1 100 Continue
Transfer-Encoding: chunked
```

### ❌ Bad 304 — content, which no permission covers

```http
HTTP/1.1 304 Not Modified
ETag: "abc"

not empty
```
