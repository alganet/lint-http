<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message ETag Syntax

## Description

Validate that the `ETag` response header contains a single, syntactically valid entity-tag (strong or weak) as defined by RFC 9110. This rule flags non-UTF-8 header values, the use of the special `*` value (which is only meaningful in conditional request headers), and the presence of multiple `ETag` header fields.

## Specifications

- [RFC 9110 §7.6 — Entity Tag](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.6)
- [RFC 9110 §8.8.3 — ETag header field](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.8.3)

## Configuration

```toml
[rules.message_etag_syntax]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good (strong ETag)

```http
HTTP/1.1 200 OK
ETag: "33a64df551425fcc55e4d42a148795d9f25f89d4"
```

### ✅ Good (weak ETag)

```http
HTTP/1.1 200 OK
ETag: W/"67ab43"
```

### ❌ Bad (`*` used in response)

```http
HTTP/1.1 200 OK
ETag: *
```

### ❌ Bad (missing quotes)

```http
HTTP/1.1 200 OK
ETag: abc
```

### ❌ Bad (multiple header fields)

```http
HTTP/1.1 200 OK
ETag: "a"
ETag: "b"
```
