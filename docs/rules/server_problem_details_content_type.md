<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# server_problem_details_content_type

## Description

Problem Details responses (RFC 7807) SHOULD use the media types `application/problem+json` or `application/problem+xml` to indicate a standardized problem representation. This rule warns when an error response (4xx/5xx) uses a generic JSON/XML media type instead of the Problem Details media types.

## Specifications

- [RFC 7807 §6](https://www.rfc-editor.org/rfc/rfc7807#section-6) — Problem Details for HTTP APIs

## Configuration

Enable the rule in your TOML config example:

```toml
[rules.server_problem_details_content_type]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
HTTP/1.1 400 Bad Request
Content-Type: application/problem+json

{"type":"https://example.com/probs/out-of-credit","title":"You do not have enough credit","status":400}
```

### ❌ Bad

```http
HTTP/1.1 500 Internal Server Error
Content-Type: application/json

{"type":"https://example.com/probs/internal","title":"Internal error","status":500}
```
