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

The field lines are read as the octets the sender wrote, so an octet outside US-ASCII is reported as the character `DIGIT` does not admit rather than as a verdict about the value's encoding — the whole production is ten visible US-ASCII characters, so there was never anything for the encoding to say first.

Improper `Content-Length` values can lead to message framing errors or truncated bodies; the rule flags invalid or inconsistent values.

## Violations

- [content_length_character_forbidden](../violations/content_length_character_forbidden.md) — Content-Length value holds an octet DIGIT does not admit
- [content_length_empty](../violations/content_length_empty.md) — Content-Length declares no length
- [content_length_members_conflicting](../violations/content_length_members_conflicting.md) — Content-Length is declared twice with different numbers
- [content_length_numeral_invalid](../violations/content_length_numeral_invalid.md) — Content-Length numeral is too large to represent

## Specifications

- [RFC 9110 §8.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.6): Where `Content-Length = 1*DIGIT` is defined — the grammar every value here is checked against
- [RFC 9112 §6.3](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.3): Why differing values are an error and why a single field line may carry a comma-separated list, provided every member is valid and identical

## Configuration

```toml
[rules.content_length_valid]
enabled = true
```

## Examples

### ✅ Good

```http
Content-Length: 0
Content-Length: 10
Content-Length:  20  
```

### ✅ Good Repeated field lines carrying one length

```http
HTTP/1.1 200 OK
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
```

### ❌ Bad Repeated field lines naming two lengths

```http
HTTP/1.1 200 OK
Content-Length: 10
Content-Length: 20
```
