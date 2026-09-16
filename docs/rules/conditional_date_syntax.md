<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Conditional Date Format

## Description

The `If-Modified-Since` (RFC 9110 §13.1.3) and `If-Unmodified-Since` (§13.1.4) request headers are each defined as an HTTP-date, and a sender MUST generate one in the IMF-fixdate format. This rule reads both against that one obligation: it flags values that are not a valid IMF-fixdate — including the two obsolete formats, which a recipient must still accept but no sender may emit — and reads each value as octets, so an octet outside visible US-ASCII is reported as a character the format does not print rather than as a verdict about the field's encoding. Which direction the comparison then runs is the server's question, not the value's.

## Specifications

- [RFC 9110 §13.1.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.3): If-Modified-Since header
- [RFC 9110 §13.1.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.4): If-Unmodified-Since header
- [RFC 9110 §5.6.7](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.7): Date/Time Formats — `HTTP-date = IMF-fixdate / obs-date`, the recipient's MUST to accept all three, and the sender's MUST to generate only the first

## Configuration

```toml
[rules.conditional_date_syntax]
enabled = true
```

## Examples

### ✅ Good

```http
GET /resource HTTP/1.1
If-Modified-Since: Wed, 21 Oct 2015 07:28:00 GMT
```

### ❌ Bad

```http
GET /resource HTTP/1.1
If-Modified-Since: not-a-date
```

```http
PUT /resource HTTP/1.1
If-Unmodified-Since: Sunday, 06-Nov-94 08:49:37 GMT
```

```http
PUT /resource HTTP/1.1
If-Unmodified-Since: \xff
```
