<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# message_charset_iana_registered

## Description

If a `Content-Type` header includes a `charset` parameter, the value SHOULD be an IANA-registered character set name (case-insensitive) or match one from an explicit allowlist. This rule detects empty or syntactically invalid `charset` values and reports unrecognized charsets according to configured policy.

## Specifications

- [RFC 9110 §6.4 — Media Type `charset` parameter semantics](https://www.rfc-editor.org/rfc/rfc9110.html#section-6.4)
- [IANA Character Sets registry](https://www.iana.org/assignments/character-sets/character-sets.xhtml)

## Configuration

```toml
[rules.message_charset_iana_registered]
enabled = true
severity = "warn"
allowed = ["utf-8", "iso-8859-1", "us-ascii"]
```

`allowed` must be an array of string names (case-insensitive) that are considered acceptable; use lower-case in examples for clarity.

## Examples

### ✅ Good

```http
GET / HTTP/1.1
Host: example.com
Content-Type: text/plain; charset=utf-8
```

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset="UTF-8"

<html>...</html>
```

### ❌ Bad

```http
HTTP/1.1 200 OK
Content-Type: text/plain; charset=unknown-charset
```

```http
HTTP/1.1 200 OK
Content-Type: text/plain; charset="unfinished
```
