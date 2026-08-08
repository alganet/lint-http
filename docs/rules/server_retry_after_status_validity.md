<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Server Retry-After Status Validity

## Description

`Retry-After` tells a user agent how long to wait before making a follow-up request. Four contexts give it a defined behaviour — one of them a whole status class — and this rule reports the field arriving anywhere else.

- any `3xx` redirection — the minimum time to wait before issuing the redirected request (RFC 9110 §10.2.3)
- `503 Service Unavailable` — how long the service is expected to be unavailable (RFC 9110 §10.2.3, §15.6.4)
- `413 Content Too Large` — when the condition is temporary, §15.5.14 **asks for the field by name**, with a SHOULD
- `429 Too Many Requests` — RFC 6585 §4, a status RFC 9110 never mentions

**No requirement is violated by a response this rule reports.** §10.2.3 defines the field with no condition on the status code, and its two "When sent with" sentences elaborate two cases rather than closing the set; neither RFC 9110 nor RFC 6585 prohibits `Retry-After` anywhere. The finding is advisory: on a status neither document pairs with the field, what a client does with the value is unspecified, so the instruction is unlikely to be acted on. Configure the severity accordingly.

A `Retry-After` in a **request** is not reported either. §10.2 places the field among response fields and §10.2.3 names the server as its sender, but no sentence forbids a client from sending one.

The list is what is written down, not a grammar — a future status definition can name the field the way §15.5.14 does, and this rule would have to learn it.

The status the field arrived on is all this rule reads. The value's syntax (`Retry-After = HTTP-date / delay-seconds`) and a repeated `Retry-After` field line belong to `message_retry_after_date_or_delay`, which reports both.

## Specifications

- [RFC 9110 §10.2.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.3): Defines Retry-After generally, with no condition on the status code, then says what it indicates on a 503 and on any 3xx
- [RFC 9110 §15.5.14](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.5.14): 413 Content Too Large: when the condition is temporary the server SHOULD generate a Retry-After header field
- [RFC 9110 §15.6.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.6.4): 503 Service Unavailable: the server MAY send a Retry-After header field
- [RFC 6585 §4](https://www.rfc-editor.org/rfc/rfc6585.html#section-4): 429 Too Many Requests: the response MAY include a Retry-After header

## Configuration

```toml
[rules.server_retry_after_status_validity]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good 503: how long the service is expected to be unavailable

```http
HTTP/1.1 503 Service Unavailable
Retry-After: 120
```

### ✅ Good Any 3xx: the minimum wait before issuing the redirected request

```http
HTTP/1.1 301 Moved Permanently
Location: /new-path
Retry-After: 30
```

### ✅ Good 429: defined by RFC 6585, which RFC 9110 does not cover. Status line and fields as §4 prints them

```http
HTTP/1.1 429 Too Many Requests
Content-Type: text/html
Retry-After: 3600
```

### ✅ Good 413 with a temporary condition: §15.5.14 asks for this field with a SHOULD

```http
HTTP/1.1 413 Content Too Large
Retry-After: 120
```

### ❌ Bad Nothing pairs the field with a 200, so a user agent is not told what to do with it

```http
HTTP/1.1 200 OK
Retry-After: 10
```

### ❌ Bad The nearest defined status is 503, and its sentence says 503

```http
HTTP/1.1 500 Internal Server Error
Retry-After: 120
```
