<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Content-Type IANA Registered

## Description

This rule checks that `Content-Type` media types (both requests and responses) are either a known, allowed media type or match an explicitly configured allowlist. This helps flag unregistered or accidental vendor types that may cause interoperability problems.

## Specifications

- [RFC 9110 §8.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3): Content-Type header and media type syntax
- [RFC 6838](https://www.rfc-editor.org/rfc/rfc6838.html): Media Type specifications and registration procedures (IANA)
- [IANA Media Types Registry](https://www.iana.org/assignments/media-types/media-types.xhtml)

## Configuration

```toml
[rules.message_content_type_iana_registered]
enabled = true
severity = "warn"
allowed = ["text/plain", "text/html", "application/json", "image/*", "+json"]
```

## Examples

### ✅ Good

```http
Content-Type: text/plain
Content-Type: application/json; charset=utf-8
Content-Type: application/ld+json
Content-Type: image/png
```

### ❌ Bad

```http
Content-Type: application/vnd.unknown
Content-Type: text/x-custom
```
