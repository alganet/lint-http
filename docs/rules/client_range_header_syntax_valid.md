<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# client_range_header_syntax_valid

## Description

Checks that the `Range` request header, when present, follows the `byte-range-set` syntax defined by RFC 7233. This rule validates the unit (e.g., `bytes=`) and that each range specifier is syntactically well-formed (numeric byte positions, suffix forms like `-500`, open-ended forms like `9500-`, and correct ordering `first <= last`).

## Specifications

- RFC 7233 §2.1: Byte Ranges and `Range` header syntax — https://datatracker.ietf.org/doc/html/rfc7233#section-2.1

## Configuration

Enable the rule in your TOML config (example):

```toml
[rules.client_range_header_syntax_valid]
enabled = true
severity = "error"
```

## Examples

✅ Good

```http
GET /big-file HTTP/1.1
Host: example
Range: bytes=0-499

GET /big-file HTTP/1.1
Host: example
Range: bytes=500-999,1000-1499

GET /big-file HTTP/1.1
Host: example
Range: bytes=-500
```

❌ Bad

```http
GET /big-file HTTP/1.1
Host: example
Range: items=0-1        # unsupported unit

GET /big-file HTTP/1.1
Host: example
Range: bytes=abc        # non-numeric

GET /big-file HTTP/1.1
Host: example
Range: bytes=5-3        # first > last
```