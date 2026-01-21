<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->
# Media Type Suffix Validity

Validate that media-type subtype suffixes (e.g., `+json`, `+xml`) use known structured-syntax suffixes. Subtype suffixes are defined by the media type registration and indicate that the media type is based on a known structured syntax (for example, `application/ld+json`).

## Description

This rule flags media types (in `Content-Type` or `Accept`) whose subtype ends with a `+suffix` that is not a recognized structured-syntax suffix. Unknown or misspelled suffixes may lead to incorrect parsing or interoperability issues.

## Specifications

- [RFC 6838 §4.2.8 — Structured Syntax Name Suffixes](https://www.rfc-editor.org/rfc/rfc6838.html#section-4.2.8)
- IANA Structured Syntax Suffix registry: https://www.iana.org/assignments/media-type-structured-suffix/media-type-structured-suffix.xhtml

## Configuration

Minimal example:

```toml
[rules.message_media_type_suffix_validity]
enabled = true
severity = "warn"
allowed = ["json", "xml", "ber", "der", "fastinfoset", "wbxml", "exi"]
```

## Examples

### ✅ Good

```http
Content-Type: application/ld+json
Content-Type: application/xml
Accept: application/vnd.example+json; q=0.8
```

### ❌ Bad — unknown suffix

```http
Content-Type: application/vnd.example+unknown
Accept: application/bar+nope
```
