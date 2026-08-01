<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Content-Length

## Description

This rule validates `Content-Length` header values for syntax and consistency:

- Each `Content-Length` header value must be a non-negative decimal integer (no signs, no decimals).
- A `Content-Length` header with an empty value or containing non-digit characters is invalid.
- When multiple `Content-Length` header fields are present, their trimmed numeric values MUST be identical.

Improper `Content-Length` values can lead to message framing errors or truncated bodies; the rule flags invalid or inconsistent values.

## Specifications

- [RFC 9110 §8.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.6): Where `Content-Length = 1*DIGIT` is defined — the grammar every value here is checked against
- [RFC 9112 §6.3](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.3): Why differing values are an error and why a single field line may carry a comma-separated list, provided every member is valid and identical

## Configuration

```toml
[rules.message_content_length]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
Content-Length: 0
Content-Length: 10
Content-Length:  20  

Content-Length: 10
Content-Length:  10 
```

### ❌ Bad

```http
Content-Length: -1
Content-Length: +1
Content-Length: 1.5
Content-Length: abc
Content-Length:

Content-Length: 10
Content-Length: 20
```
