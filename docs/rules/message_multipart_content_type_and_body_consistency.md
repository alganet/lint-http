<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# message_multipart_content_type_and_body_consistency

## Description

When a `Content-Type` header declares `multipart/*` it MUST include a `boundary` parameter and the corresponding message body (when present) MUST use that boundary to delimit parts. This rule verifies that when a `multipart/*` Content-Type provides a boundary and a captured body is available, the body contains at least one boundary marker (`--<boundary>`) and a terminating boundary (`--<boundary>--`). Missing markers indicate a malformed or truncated multipart body and may break message parsing.

## Specifications

- [RFC 2046 §5.1.1 — Multipart common syntax and the `boundary` parameter](https://www.rfc-editor.org/rfc/rfc2046.html#section-5.1.1)

## Configuration

Minimal example to enable the rule (default severity is `warn`):

```toml
[rules.message_multipart_content_type_and_body_consistency]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
HTTP/1.1 200 OK
Content-Type: multipart/mixed; boundary=abc

--abc
Content-Type: text/plain

hello
--abc--
```

```http
HTTP/1.1 200 OK
Content-Type: multipart/mixed; boundary="a b"

--a b
Content-Type: text/plain

hello
--a b--
```

### ❌ Bad (missing boundary)

```http
HTTP/1.1 200 OK
Content-Type: multipart/mixed; boundary=abc

no boundaries here
```

### ❌ Bad (missing final boundary)

```http
HTTP/1.1 200 OK
Content-Type: multipart/mixed; boundary=abc

--abc
Content-Type: text/plain

hello
--abc
```
