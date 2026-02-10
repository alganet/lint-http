<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# server_200_vs_204_body_consistency

## Description

Warn when a server returns a 200 (OK) response that contains no message body and the request method is not `HEAD`. When a response intentionally has no content, the `204 No Content` status code is a more appropriate and explicit choice. This rule helps catch server misconfigurations that return `200` with an empty payload where `204` would better express the intent.

## Specifications

- [RFC 9110 §15.3.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.3.1): 200 (OK) response semantics — expected to contain message content unless the message framing explicitly indicates zero length; consider using 204 when no content is preferred.
- [RFC 9110 §15.3.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.3.5): 204 (No Content) — indicates the server intentionally sends no content.
- [RFC 9110 §6.4.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-6.4.2): Identifying content — rules for when responses are considered to have no content (e.g., HEAD requests or 204 responses).

## Configuration

```toml
[rules.server_200_vs_204_body_consistency]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 27

{"status":"ok","data":1}
```

### ✅ Good (HEAD request)

```http
HEAD /resource HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
Date: Mon, 01 Jan 2024 00:00:00 GMT

```

### ❌ Bad

```http
HTTP/1.1 200 OK
Content-Length: 0

```

This rule is conservative: it reports when there's clear evidence of "no content" (for example, a numeric `Content-Length` of `0` or a captured decoded body length of zero) and does not attempt to speculate when content presence is unknown (no `Content-Length`, no `Transfer-Encoding`, and no captured body length).
