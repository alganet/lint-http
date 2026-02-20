<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Server Retry-After Status Validity

## Description

`Retry-After` is primarily defined for temporary unavailability and redirects. This rule flags responses that include `Retry-After` on statuses where its semantics are unusual.

The rule allows `Retry-After` on:
- `503 Service Unavailable` (RFC 9110)
- any `3xx` redirection (RFC 9110)
- `429 Too Many Requests` (RFC 6585)

## Specifications

- [RFC 9110 §10.2.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.3): Retry-After with 503 and 3xx responses
- [RFC 6585 §4](https://www.rfc-editor.org/rfc/rfc6585.html#section-4): 429 Too Many Requests may include Retry-After

## Configuration

```toml
[rules.server_retry_after_status_validity]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
HTTP/1.1 503 Service Unavailable
Retry-After: 120

HTTP/1.1 301 Moved Permanently
Location: /new-path
Retry-After: 30

HTTP/1.1 429 Too Many Requests
Retry-After: 60
```

### ❌ Bad

```http
HTTP/1.1 200 OK
Retry-After: 10

HTTP/1.1 500 Internal Server Error
Retry-After: 120
```

