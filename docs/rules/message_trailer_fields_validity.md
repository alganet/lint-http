<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Trailer Fields Validity

## Description

Validates that actual trailer fields sent after the message body do not contain prohibited headers and are consistent with any `Trailer` header declaration.

RFC 9110 §6.5.1 forbids trailer fields used for message framing (`Transfer-Encoding`, `Content-Length`), routing (`Host`), request modifiers (controls and conditionals such as `Cache-Control`, `If-Match`, `Range`), authentication (`Authorization`, `WWW-Authenticate`), response control data (`Date`, `Location`, `Vary`), or payload processing (`Content-Type`, `Content-Encoding`, `Content-Range`, `Trailer` itself). Hop-by-hop headers (`Connection`, `Keep-Alive`, `Upgrade`) are also prohibited.

When a `Trailer` header is present in the message headers, this rule additionally checks that all actual trailer fields were declared, since senders SHOULD list expected trailer fields before the message body.

This rule complements `message_trailer_headers_valid`, which validates the `Trailer` header declaration itself (field-name syntax and hop-by-hop restrictions). This rule instead validates the **actual trailer fields** that appear after the body.

## Specifications

- [RFC 9110 §6.5 — Trailer Fields](https://www.rfc-editor.org/rfc/rfc9110.html#section-6.5)
- [RFC 9110 §6.5.1 — Limitations on Use of Trailers](https://www.rfc-editor.org/rfc/rfc9110.html#section-6.5.1)
- [RFC 9112 §7.1.2 — Chunked Transfer Coding (Trailer Section)](https://www.rfc-editor.org/rfc/rfc9112.html#section-7.1.2)

## Configuration

```toml
[rules.message_trailer_fields_validity]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
HTTP/1.1 200 OK
Trailer: X-Checksum
Transfer-Encoding: chunked

<chunked body>
X-Checksum: abc123
```

### ❌ Bad

```http
HTTP/1.1 200 OK
Transfer-Encoding: chunked

<chunked body>
Content-Length: 42
```

```http
HTTP/1.1 200 OK
Trailer: X-Checksum
Transfer-Encoding: chunked

<chunked body>
X-Signature: sig-value
```
