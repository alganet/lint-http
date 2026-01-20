<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# message_accept_and_content_type_negotiation

## Description

Validate that a server response's `Content-Type` matches the client's `Accept` header when present. If the request provides an `Accept` header that does not allow the response media type (for example `Accept: application/json` but response `Content-Type: text/html`), the server should consider returning `406 Not Acceptable` or use a matching representation.

## Specifications

- [RFC 9110 §12.5.1 — Accept (media ranges and q-values)](https://www.rfc-editor.org/rfc/rfc9110.html#section-12.5.1)
- [RFC 9110 §12.4.2 — Quality values (q parameter)](https://www.rfc-editor.org/rfc/rfc9110.html#section-12.4.2)
- [RFC 9110 §15.5.7 — 406 Not Acceptable](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.5.7)

## Configuration

Minimal example to enable this rule:

```toml
[rules.message_accept_and_content_type_negotiation]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
GET /resource HTTP/1.1
Accept: application/json

HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
```

### ❌ Bad

```http
GET /resource HTTP/1.1
Accept: application/json

HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
```
