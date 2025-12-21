<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Content-Type Well-Formed

## Description

This rule checks that `Content-Type` headers (both requests and responses) parse as a valid `media-type` with a non-empty type and subtype and well-formed parameters when present. This helps ensure downstream components and user agents can interpret the media type and parameters reliably.

## Specifications

- [RFC 9110 §6.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-6.4): Content-Type header and media type syntax
- [RFC 7231 §3.1.1.1](https://www.rfc-editor.org/rfc/rfc7231#section-3.1.1.1): Media type semantics

## Configuration

```toml
[rules.message_content_type_well_formed]
enabled = true
severity = "warn"
```

## Examples

✅ Good

```http
Content-Type: text/plain
Content-Type: application/json; charset=utf-8
Content-Type: image/vnd.example+json; foo="bar"; charset=utf-8
```

❌ Bad

```http
Content-Type: text
Content-Type: text/
Content-Type: */plain
Content-Type: text/plain; badparam
Content-Type: text/plain; charset="unclosed
```
