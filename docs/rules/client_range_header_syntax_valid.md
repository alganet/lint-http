<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Client Range Header Syntax Valid

## Description

Checks that the `Range` request header, when present, follows the `byte-range-set` syntax defined by RFC 9110. This rule validates the unit (e.g., `bytes=`) and that each range specifier is syntactically well-formed (numeric byte positions, suffix forms like `-500`, open-ended forms like `9500-`, and correct ordering `first <= last`).

## Specifications

- [RFC 9110 §14.1.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-14.1.2): Range header syntax

## Configuration

```toml
[rules.client_range_header_syntax_valid]
enabled = true
severity = "error"
```

## Examples

### ✅ Good

```http
GET /big-file HTTP/1.1
Host: example.com
Range: bytes=0-499

GET /big-file HTTP/1.1
Host: example.com
Range: bytes=500-999,1000-1499

GET /big-file HTTP/1.1
Host: example.com
Range: bytes=-500
```

### ❌ Bad

```http
GET /big-file HTTP/1.1
Host: example.com
Range: items=0-1
# unsupported unit

GET /big-file HTTP/1.1
Host: example.com
Range: bytes=abc
# non-numeric

GET /big-file HTTP/1.1
Host: example.com
Range: bytes=5-3
# first > last
```