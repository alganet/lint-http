<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Server Content-Type Present

## Description

Reports a response that carries content without a `Content-Type` describing it.

**This is a SHOULD, and it has a stated exception.** RFC 9110 §8.3: "A sender that generates a message containing content SHOULD generate a Content-Type header field in that message *unless the intended media type of the enclosed representation is unknown to the sender*." Nothing on the wire separates a sender that did not know from one that did not bother, so both are reported — the finding is that the recipient was left to guess, not that a rule was broken.

**Why the guess matters.** §8.3 gives a recipient two ways to proceed without the field: assume `application/octet-stream`, or examine the data. The second is content sniffing, and §8.3 spends a paragraph on it — it "risks drawing incorrect conclusions about the data, which might expose the user to additional security risks (e.g., \"privilege escalation\")".

**Content, not headers.** The condition is that the message *contains content*, so the recorded body length decides it wherever one was captured. Only where nothing was captured does the rule fall back to header evidence, and then only to signals that assert content — a non-zero `Content-Length` or a `Transfer-Encoding`. A 2xx that merely omits `Content-Length` is not evidence of a body; that is what an empty HTTP/2 response looks like.

**Responses with nothing to describe are skipped**: `1xx`, `204`, `304` (RFC 9112 §6.3), `205` (RFC 9110 §15.3.6's MUST NOT), any response to `HEAD` (§9.3.2), and a `2xx` to `CONNECT`, whose trailing octets are a tunnel rather than content. Whether a HEAD response should still carry the `Content-Type` a `GET` would have sent is §9.3.2's same-header-fields SHOULD, which `head_response_headers_match_get` checks against the actual `GET`.

## Specifications

- [RFC 9110 §8.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3): Content-Type — the SHOULD, the exception that excuses a sender who does not know the type, the recipient's two fallbacks, and what sniffing costs
- [RFC 9112 §6.3](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.3): Message body length — item 1 for the statuses and HEAD responses that carry no content, item 2 for CONNECT tunnels, item 8 for why a missing Content-Length is not evidence of a body
- [RFC 9110 §15.3.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.3.6): 205 Reset Content — bodiless by its own MUST NOT, and absent from §6.3's list
- [RFC 9110 §9.3.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.2): HEAD — no content is sent, so this rule's condition is never met; the same-header-fields SHOULD is another rule's subject

## Configuration

```toml
[rules.content_type_present]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
GET /page HTTP/1.1

HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 3

abc
```

### ✅ Good (no content, so nothing to describe)

```http
GET /thing HTTP/1.1

HTTP/1.1 204 No Content
```

### ✅ Good (a HEAD response sends no content)

```http
HEAD /large.iso HTTP/1.1

HTTP/1.1 200 OK
Content-Length: 1048576
```

### ❌ Bad (the recipient is left to sniff)

```http
GET /page HTTP/1.1

HTTP/1.1 200 OK
Content-Length: 3

abc
```
