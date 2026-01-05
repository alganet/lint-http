<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Server Response 405 Allow

## Description

This rule checks if `405 Method Not Allowed` responses include an `Allow` header.

The `Allow` header is required in `405` responses to indicate the set of methods supported by the resource, so clients can discover what operations are permitted.

## Specifications

- [RFC 9110 §10.5.6](https://www.rfc-editor.org/rfc/rfc9110.html#name-405-method-not-allowed): 405 Method Not Allowed
- [RFC 9110 §10.2.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.1): Allow header

## Configuration

```toml
[rules.server_response_405_allow]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good Response

```http
HTTP/1.1 405 Method Not Allowed
Content-Type: text/plain
Allow: GET, HEAD
```

### ❌ Bad Response

```http
HTTP/1.1 405 Method Not Allowed
Content-Type: text/plain
# Missing Allow header
```
