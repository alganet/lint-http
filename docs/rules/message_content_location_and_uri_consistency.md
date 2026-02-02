<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# message_content_location_and_uri_consistency

## Description

Validate `Content-Location` header values to ensure they are well-formed URI references and, for 2xx responses, that they consistently identify the representation. If the response's `Content-Location` resolves to the same URI as the request target, the response clearly identifies the representation of the target resource; otherwise, the header indicates the representation is identified by a different URI (allowed, but worth flagging).

## Specifications

- [RFC 9110 §8.7 — Content-Location](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.7)

## Configuration

This rule uses the standard `enabled` + `severity` configuration (no extra keys required).

Example:

```toml
[rules.message_content_location_and_uri_consistency]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
GET /foo HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
Content-Location: /foo
Content-Type: text/plain

Hello
```

### ✅ Good (absolute)

```http
GET /foo HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
Content-Location: http://example.com/foo
Content-Type: text/plain

Hello
```

### ❌ Bad (invalid percent-encoding)

```http
HTTP/1.1 200 OK
Content-Location: /bad%2G
```

### ❌ Bad (contains whitespace)

```http
HTTP/1.1 200 OK
Content-Location: /bad path
```
