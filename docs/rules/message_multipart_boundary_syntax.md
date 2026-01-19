<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# message_multipart_boundary_syntax

## Description

Validate that `Content-Type: multipart/*` includes a required `boundary` parameter and that the boundary value follows the rules in RFC 2046 §5.1.1: the boundary value, after optional quoted-string processing and unescaping, must be between 1 and 70 characters, must not end with whitespace, and must only contain characters from the defined set (letters, digits, and "'() + _ , - . / : = ?" and space when quoted).

## Specifications

- [RFC 2046 §5.1.1 — Multipart common syntax and boundary parameter](https://www.rfc-editor.org/rfc/rfc2046.html#section-5.1.1)

## Configuration

```toml
[rules.message_multipart_boundary_syntax]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
Content-Type: multipart/mixed; boundary=gc0p4Jq0M2Yt08j34c0p
```

```http
Content-Type: multipart/mixed; boundary="gc0pJq0M:08jU534c0p"
```

### ❌ Bad

```http
Content-Type: multipart/mixed
```

```http
Content-Type: multipart/mixed; boundary=
```

```http
Content-Type: multipart/mixed; boundary=""
```

```http
Content-Type: multipart/mixed; boundary="abc "  # must not end in whitespace
```

```http
Content-Type: multipart/mixed; boundary=gc0pJq0M:08jU534c0p  # colon must be quoted
```
